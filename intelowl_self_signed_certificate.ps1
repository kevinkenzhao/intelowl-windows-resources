#https://4sysops.com/archives/export-certificate-as-cer-der-p7b-or-pfx/
#https://stackoverflow.com/questions/29556437/how-to-return-one-and-only-one-value-from-a-powershell-function
#All output is captured, and returned. The return keyword really just indicates a logical exit point.

[CmdletBinding()]
param(
    [string][Parameter(Mandatory=$false)]$workingDir,
    [string][Parameter(Mandatory=$false)]$certname
)
    
if (!([bool]$workingDir)){
    [string]$workingDir = "$env:userprofile"
    #Write-Output $workingDir
}
if (!([bool]$certname)){
	[string]$certname = "intelowl-prd.local"
    #Write-Output $certname
}

Function generateDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$directory
    )
	if (!(Test-Path -path $directory)) {New-Item $directory -Type Directory | Out-Null}
}

Function generateCertificate {
    <#
    .DESCRIPTION
        Create a self-signed certificate issued to "CN=intelowl-prd.local" (or a CN of choice) and export the newly created certificate in DER-encoded format. Then, convert said certificate into PEM-encoded format and update the wrapping header/trailer.
    .PARAMETER certname
        Set the CN for the x509 certificate
    #>

    [string]$certnameDER = -join($certname, '_DER')
    [string]$DERCert = "$workingDir\$certnameDER.cer"
    [string]$Base64Cert = "$workingDir\ca-certificates\$certname.cer"

	$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -DnsName "$certname" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256

	Export-Certificate -Cert $cert -FilePath $DERCert | Out-Null #Type parameter supports CERT, P7B, and SST (Default: CERT)

	generateDirectory -directory "$workingDir\private"
	generateDirectory -directory "$workingDir\ca-certificates"

	Start-Process -FilePath 'certutil.exe' -ArgumentList "-encode $DERCert $Base64Cert" -WindowStyle Hidden -Wait
    Remove-Item -Path $DERCert

	#Update header/trailer of PEM certificate
	(Get-Content $Base64Cert).Replace('BEGIN CERTIFICATE', 'BEGIN TRUSTED CERTIFICATE').Replace('END CERTIFICATE','END TRUSTED CERTIFICATE') | Set-Content -Force $Base64Cert

}

Function extractPrivateKey {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$True)]$certname
    )
	$cert = $(Get-ChildItem Cert:\CurrentUser\My -Recurse | ? {$_.Subject -eq "CN=$certname"})
    #Write-Host $cert
	$RSACng = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
	$KeyBytes = $RSACng.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
	$KeyBase64 = [System.Convert]::ToBase64String($KeyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
	$KeyPem = -Join("-----BEGIN PRIVATE KEY-----`n",$KeyBase64,"`n-----END PRIVATE KEY-----")
	Write-Output $KeyPem | Set-Content -Path "$workingDir\private\$certname.key"

	return $cert
}

Function addToTrustedStore {
    <#
    .DESCRIPTION
        Add certificate to Trusted Root Certification Authorities store
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$cert
    )
	$store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root,"LocalMachine")
	$store.Open("ReadWrite")
	$store.Add($cert)
	$store.Close()
}

Function ExportPFX {
    <#
    .DESCRIPTION
        Export certificate as a PFX bundle
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$cert
    )
	$b=@()
	65..90 | % { $b += %{"$([char]$_)"}}
	48..57 | % { $b += %{"$([char]$_)"}}
	97..122 | % { $b += %{"$([char]$_)"}}
	$pw = (Get-Random -Count 15 -InputObject $b) -join ''
	$mypwd = ConvertTo-SecureString -String $pw -Force -AsPlainText
	Export-PfxCertificate -Cert $cert -FilePath "$workingDir\$certname.pfx" -Password $mypwd
	Write-Output "The import password is: $pw"
}

generateCertificate
$cert = extractPrivateKey -certname $certname
Copy-item -Force -Recurse "$workingDir\private" -Destination "$workingDir\IntelOwl"
Copy-item -Force -Recurse "$workingDir\ca-certificates" -Destination "$workingDir\IntelOwl"
addToTrustedStore -cert $cert
#ExportPFX -cert $cert