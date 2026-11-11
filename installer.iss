; Inno Setup Script for VAULT (Item 33)
; Generates VAULT-Setup-1.0.0.exe for per-user installation (no UAC / admin required)

#define MyAppName "VAULT"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "VAULT Security"
#define MyAppExeName "VAULT.exe"
#define MyAppId "{{A6E2458B-3D79-4B52-9A4B-916A467D2841}}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DisableProgramGroupPage=yes
OutputDir=release
OutputBaseFilename=VAULT-Setup-{#MyAppVersion}
SetupIconFile=vault.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Copy all binaries and data from PyInstaller onedir distribution
Source: "dist\VAULT\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// Explicitly preserve user vault database and logs in %APPDATA%\VAULT
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    MsgBox('VAULT has been uninstalled.' + #13#10 + #13#10 +
           'Your encrypted vault database and logs in %APPDATA%\VAULT have been kept intact to prevent data loss.',
           mbInformation, MB_OK);
  end;
end;
