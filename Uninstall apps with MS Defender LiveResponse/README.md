# Uninstall-App.ps1

You want to uninstall some applications with Microsoft Defender Live-Response?
Use this script in combination with the ApplicationInfo.json to uninstall every app you want.

Paramters of the scirpt are:
- AppName (The names of the app that should be uninstalled.)
- Ignore (Will ignore the code signing of the uninstalltion executable.)

# ApplicationInfo.json

We need several information for the applications that should be uninstalled.
In ApplicationInfo.json these information are stored:
- ApplicationName
- MinimumVersion
- VendorName
These three properties are needed. The values of these properties needs to match the registry entries.

If you have the uninstallation string of an application, you can add addtional properties:
- UninstallString
- Parameter
- CodeSigningSubject


| Property           |      Format      | Mandotory |
| :----------------- | :--------------: | :-------: |
| ApplicationName    |      string      |   True    |
| MinimumVersion     |     version      |   True    |
| VendorName         |      string      |   True    |
| UninstallString    |      string      |   False   |
| Parameter          | array of strings |   False   |
| CodeSigningSubject |      string      |   False   |



