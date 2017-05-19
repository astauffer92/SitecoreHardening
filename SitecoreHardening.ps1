<# 
Author(s): Bruce Lee, Grant Killian, Kelly Rusk, Jimmy Rudley

Created Date: August 4, 2016
Modified Date: May 3, 2017

This is the Rackspace Managed Services for Sitecore (https://www.rackspace.com/digital/sitecore) script for security hardening a Sitecore environment 

If the Execution Policy does not allow execution, you may need to run the following interactively to allow a scoped session bypass. 
This is secure as it requires interaction on server and cannot be executed from a script:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

1. Deny anonymous users access to key folders
2. Disable client RSS feeds
3. Secure the file upload functionality
4. Improve the security of the website folder
5. Increase login security
6. Limit access to certain file types
7. Protect PhantomJS
8. Protect media requests
9. Remove header information from responses sent by your website

### updated for May 2017 to include these next steps:
10. Change the hash algorithm for password encryption
11. Disable WebDav
12. Remove the xslHelper extension
13. Enforce a strong password policy

#>



$siteNamePrompt = Read-Host "enter website name"
$site = get-website -name $siteNamePrompt

# read in Web.config
$webConfigPath = "{0}\web.config" -f $site.physicalPath


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 1 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Deny anonymous users access to key folders 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$filterString = "/system.Webserver/security/authentication/anonymousauthentication"
$app_ConfigLocation = "{0}/App_Config" -f $siteNamePrompt
$adminLocation = "{0}/sitecore/admin" -f $siteNamePrompt
$debugLocation = "{0}/sitecore/debug" -f $siteNamePrompt
$ShellWebserviceLocation = "{0}/sitecore/shell/webservice" -f $siteNamePrompt
Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $app_ConfigLocation
Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $adminLocation
Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $debugLocation
Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $ShellWebserviceLocation

Write-Output "Step 1 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Disable client RSS feeds
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[xml] $webConfigXML = Get-Content $webConfigPath
#remove the following handler in the <httpHanderls> section in the web.config
$targetName = "Sitecore.FeedRequestHandler"
$nodePath = "configuration/system.webServer/handlers/add[@name='{0}']" -f $targetName
$node = $webConfigXML.SelectSingleNode($nodePath)
if($node -ne $null)
{
    $webConfigXML.configuration.'system.webServer'.handlers.RemoveChild($node)
}
$webConfigXML.Save($webConfigPath)

Write-Output "Step 2 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 3 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Secure the file upload functionality
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#Deny Script and Execute permission on /upload folder
$psPath = "MACHINE/WEBROOT/APPHOST/{0}/upload" -f $site.name
$filter = "system.webServer/handlers/@AccessPolicy"
Set-WebConfiguration -Filter $filter -Value "Read" -PSPath $psPath

#Deny Script and Execute permission on /temp folder
$psPath = "MACHINE/WEBROOT/APPHOST/{0}/temp" -f $site.name
$filter = "system.webServer/handlers/@AccessPolicy"
Set-WebConfiguration -Filter $filter -Value "Read" -PSPath $psPath

#Remove the SitecoreUploadWatcher         
$xml = [xml](get-content $webConfigPath) 
foreach( $item in  $xml.configuration."system.webServer".modules.add )             
{
        if( $item.name -eq "SitecoreUploadWatcher" )                                                 
        {
              $xml.configuration."system.webServer".modules.RemoveChild($item);   
        }
}

$xml.Save($webConfigPath) 


if( !(test-path "C:\localStaging") )
{
    mkdir "C:\localStaging"
}

#Setup the UploadFilter (.dll and .config)
$sitecoreRoot = $site.physicalPath              			
$downLoadURI = "https://upload.infocentricresearch.com/access/2017-05-19_15-13--2y11ve9qoEwngfrPMn6alN6PtvUtGEQ7j0PVsARxI5xJVkXjavj7hQIC/UploadFilter.config.zip"
$downLoadZipPath1 = "C:\localStaging\UploadFilter.config"
Invoke-WebRequest -Uri $downLoadURI -OutFile $downLoadZipPath

$downLoadURI = "https://upload.infocentricresearch.com/access/2017-05-19_15-13--2y11y8AwmNfJymXT4gZoo8btyuBMBN5unbsZCKgzcSRIvvYK874Fz0a/Sitecore.UploadFilter.dll.zip"
$downLoadZipPath2 = "C:\localStaging\Sitecore.UploadFilter.dll"
Invoke-WebRequest -Uri $downLoadURI -OutFile $downLoadZipPath

$WebsiteBin = "{0}\Website\bin" -f $sitecoreRoot 
$WebsiteConfig = "{0}\Website\app_config\include" -f $sitecoreRoot 
Copy-Item -Path $downLoadZipPath1 -Destination $WebsiteConfig
Copy-Item -Path $downLoadZipPath2 -Destination $WebsiteBin

Write-Output "Step 3 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 4 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Improve the security of the website folder
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#This is mostly handled during our scripted install; this is a snippet from those procedures
#$sitecoreDataDirectory = "D:/outside/of/webroot"
$sitecoreAppIncludeDirectory = "{0}\app_config\include" -f $sitecoreRoot 
$infocentricInclude = $sitecoreAppIncludeDirectory + "\Z.Infocentric"
#
if( !(test-path $infocentricInclude) )
{
    mkdir $infocentricInclude
}
#
#
#$dataFolderConfigPath = "{0}\DataFolder.config.example" -f $sitecoreAppIncludeDirectory
#[xml]$dataConfigXML = Get-Content $dataFolderConfigPath
#$dataConfigXML.configuration.sitecore.'sc.variable'.attribute.'#text' = $sitecoreDataDirectory
#$dataConfigXML.Save($dataFolderConfigPath)
#$newFilename = (Get-ChildItem $dataFolderConfigPath).BaseName
#Rename-Item -Path $dataFolderConfigPath -NewName $newFilename
#
Write-Output "Step 4 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 5 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Increase login security
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# this .config is what we're applying: https://gist.github.com/grant-killian/b64aa6cabd18e9b0097257ee4a2dc614
$downLoadURI = "https://gist.githubusercontent.com/grant-killian/b64aa6cabd18e9b0097257ee4a2dc614/raw"
$downLoadPath = "C:\localStaging\Rackspace.SecurityHardening.Step5.IncreaseLoginSecurity.config"
Invoke-WebRequest -Uri $downLoadURI -OutFile $downLoadPath
Copy-Item -Path $downLoadPath -Destination $infocentricInclude #we use a "Z.Infocentric" directory under /app_config/include

Write-Output "Step 5 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 6 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Limit access to certain file types
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$psPath = "MACHINE/WEBROOT/APPHOST/{0}" -f $site.name
$filter = "system.webServer/handlers/"
New-WebHandler -Path *.xml -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "xml (integrated)" -Precondition integratedMode -PSPath $psPath
New-WebHandler -Path *.xslt -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "xslt (integrate)" -Precondition integratedMode -PSPath $psPath
New-WebHandler -Path *.config.xml -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "config.xml (integrate)" -Precondition integratedMode -PSPath $psPath
New-WebHandler -Path *.mrt -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "mrt (integrate)" -Precondition integratedMode -PSPath $psPath
    
Write-Output "Step 6 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 7 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Protect PhantomJS --generally not suitable for Content Management (CM) servers
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#$dataFolderConfigPath = "{0}\App_Config\Include\DataFolder.config" -f $site.physicalPath
#[xml] $dataFolderConfigXML = Get-Content $dataFolderConfigPath
#$dataFolderValue = $dataFolderConfigXML.configuration.sitecore.'sc.variable'.attribute.'#text'
#$phantomToolPath = "{0}\tools\phantomjs" -f $dataFolderValue
#Remove-Item -Recurse -Path $phantomToolPath
#
#
## this .config is what we're applying: https://gist.github.com/grant-killian/16b9ec61190d43441fbca9007167feef
#$downLoadURI = "https://gist.githubusercontent.com/grant-killian/16b9ec61190d43441fbca9007167feef/raw"
#$downLoadPath = "C:\localStaging\Rackspace.SecurityHardening.Step7.ProtectPhantomJS.config"
#Invoke-WebRequest -Uri $downLoadURI -OutFile $downLoadPath
#Copy-Item -Path $downLoadPath -Destination $infocentricInclude #we use a "Z.Infocentric" directory under /app_config/include
#
#Write-Output "Step 7 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 8 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Protect Media Requests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# this .config is what we're applying: https://gist.github.com/grant-killian/136b165ed632acf799ba95f9b91578bb
$downLoadURI = "https://gist.githubusercontent.com/grant-killian/136b165ed632acf799ba95f9b91578bb/raw"
$downLoadPath = "C:\localStaging\Rackspace.SecurityHardening.Step8.ProtectMediaRequests.config"
Invoke-WebRequest -Uri $downLoadURI -OutFile $downLoadPath

#set the implementation guid -- the gist just has a placeholder
(Get-Content $downLoadPath).replace("your-implementation-custom-guid-here", "58d36579-94c3-42d8-802f-b7cc62121d47") | Set-Content $downLoadPath

Copy-Item -Path $downLoadPath -Destination $infocentricInclude #we actually use a "Z.Infocentric" directory under /app_config/include

Write-Output "Step 8 completed"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 9 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Remove header information from responses sent by your website
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$webConfigPath = "{0}\web.config" -f $site.physicalPath
[xml]$webConfigXML = Get-Content $webConfigPath
#Remove the X-Aspnet-Version HTTP header
$webConfigXML.configuration.'system.web'.httpRuntime.SetAttribute("enableVersionHeader","false")
$webConfigXML.Save($webConfigPath)

#Remove the X-Powered-By Http header
$psPath = "MACHINE/WEBROOT/APPHOST/{0}" -f $site.name
$filter = "system.webServer/httpProtocol/customHeaders"
Remove-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name . -AtElement @{name='X-Powered-By'}

#Reminder to apply this one through implementation code

$caveat = @"
  Missing change from the Sitecore recommendations regarding 'Remove the X-AspNetMvc-Version HTTP header'
     -this is an implementation specific element that should come from source control etc
     consider an HTTP Module (instead of Global.asax)
     See the bottom of Akshay Sura's post for details:
        http://www.akshaysura.com/2016/08/02/secure-sitecore-headers-are-a-headache-but-nothing-we-cannot-solve/
  Do not forget this step!
"@

Write-Host $caveat -ForegroundColor DarkYellow

Write-Output "Step 9 completed"

################# adding these next 4 in May 2017 ################# 

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 10 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Change the hash algorithm for password encryption 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$webConfigPath = "{0}\web.config" -f $site.physicalPath
$webConfigXML = Get-Content $webConfigPath
#in the <membership> node, set the hashAlgorithmType setting to the appropriate value. Sitecore recommends SHA512:
# was <membership defaultProvider="sitecore" hashAlgorithmType="SHA1">
# will be <membership defaultProvider="sitecore" hashAlgorithmType="SHA512">                                                                 
$webConfigXML.configuration.'system.web'.membership.SetAttribute("hashAlgorithmType","SHA512")
$webConfigXML.Save($webConfigPath)
$caveat = @"
	You must reset the passwords for any accounts that used the previous algorithm, including sitecore/admin!  See https://gist.github.com/grant-killian/d2c17ec90adc4b1b99b6089172268571 for an examaple of how you could do this.
"@
Write-Host $caveat -ForegroundColor DarkYellow

Write-Output "Step 10 completed"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 11 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Disable WebDav
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$webDavConfigPath = "{0}\App_Config\Include\Sitecore.WebDAV.config" -f $site.physicalPath
$webDavConfigDisabledPath = "{0}\App_Config\Include\Sitecore.WebDAV.config.disabled" -f $site.physicalPath
Rename-Item $webDavConfigPath $webDavConfigDisabledPath

Write-Output "Step 11 completed"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 12 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Remove Xsl.SqlHelper
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$sitecoreConfigPath = "{0}\App_Config\Sitecore.config" -f $site.physicalPath
#looking to remove:
# <xslExtensions>
#    <extension mode="on" type="Sitecore.Xml.Xsl.SqlHelper, Sitecore.Kernel" namespace="http://www.sitecore.net/sc" singleInstance="true"/>
$configXML = [xml](get-content $sitecoreConfigPath) 
foreach( $item in  $configXML.sitecore.xslExtensions.extension )             
{
        if( $item.type -eq "Sitecore.Xml.Xsl.SqlHelper, Sitecore.Kernel" )                                                 
        {
              $configXML.sitecore.xslExtensions.RemoveChild($item);   
        }
}  
$configXML.Save($sitecoreConfigPath)

Write-Output "Step 12 completed"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 13 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Tune the password settings to create a strong password policy
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$webConfigPath = "{0}\web.config" -f $site.physicalPath
$webConfigXML = Get-Content $webConfigPath

<#
These are the settings, probably should tweak to suit given Sitecore implementation preferences since there is some overlap:
    -minRequiredPasswordLength
    -minRequiredNonAlphanumericCharacters
    -maxInvalidPasswordAttempts
    -passwordAttemptWindow
    -passwordStrengthRegularExpression 
    -requiresQuestionAndAnswer 
    see https://msdn.microsoft.com/en-us/library/system.web.security.membership_properties%28v=vs.110%29.aspx for details
#>
$node = $webConfigXML.configuration.'system.web'.membership.providers.add | where {$_.name -eq 'sql'}
$node.SetAttribute("minRequiredPasswordLength", "6")
$node.SetAttribute("minRequiredNonalphanumericCharacters", "1")
$node.SetAttribute("maxInvalidPasswordAttempts", "3")
$node.SetAttribute("requiresQuestionAndAnswer", "false")
$node.SetAttribute("passwordAttemptWindow", "30") #time window in minutes; default is 10 mins
#Regex rules for this example: allow all chars and requires at least 1 number and requiring at least 6 chars
$node.SetAttribute("passwordStrengthRegularExpression", "^.*(?=.{6,})(?=.*\d).*$")
                                                                
$webConfigXML.Save($webConfigPath)

Write-Output "Step 13 completed"


