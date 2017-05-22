# Sitecore Hardening
This repository helps to harden sitecore.
It does the following changes to the installation:

 * Deny anonymous users access to key folders (App_Config, sitecore/admin, sitecore/debug, sitecore/shell/webservice)
 * Disable client RSS feed
 * Secure file upload functionality
 * Improve security of website folder (adds a include folder /Z.Infocentric for hardening configs)
 * Increase login security
 * Limit access to certain file types
 * Protect media requests
 * Remove header information from responses sent by your website
 * Change the hash algorithm for password encryption 
 * Disable WebDav
 * Remove Xsl.SqlHelper
 * Tune the password settings to create a strong password policy

## Step by Step Guide

### Setup
Copy the file SitecoreHardening.ps1 to the server you want to harden.

### Run the script
Open powershell with admin rights
CD to the location where you placed the script in 
Type "SitecoreHardening.ps1" and press enter

### Delete the script
Remove the script completely from the server

### Reset admin account password
Because we changed the hash algorythm for passwords, the admin and all others can no longer login.
To give admin user access again, copy the file "ResetSitecorePassword.aspx" from the repository to your IIS root.
Now open your browser and open the following URL [BaseUrl]/ResetSitecorePassword.aspx.
Note down the password you get displayed in the browser.

### Check login
Try if login with admin account works again.

### Delete the .aspx
Now delete ResetSitecorePassword.aspx completely from your server
