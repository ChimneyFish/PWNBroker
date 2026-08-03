; PwnBroker Agent — Windows installer (Inno Setup)
;
; Wraps the PyInstaller-frozen agent.exe (see pwnbroker_agent.spec) in a
; standalone installer. Unlike the PowerShell installer, this binary has no
; Python/pip/venv dependency at all on the target machine — it's a single
; compiled service executable — so it doesn't hit any of the Python-detection,
; pip-cache-warning, or pywin32-post-install issues that script chases.
;
; Build (after `pyinstaller pwnbroker_agent.spec` has produced dist\pwnbroker_agent\):
;   iscc pwnbroker_agent.iss
;   iscc /DMyAppVersion=1.2.3 pwnbroker_agent.iss     (stamp a specific version)
;
; Silent / Intune / GPO install (no UI, no prompts):
;   PwnBrokerAgentSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART ^
;     /SERVER=https://pwnbroker.example.com /REGTOKEN=xxxxx [/NOVERIFYSSL=1]
;
; Uninstall:
;   "{app}\unins000.exe" /VERYSILENT

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#define MyAppName "PwnBroker Agent"
#define MyAppPublisher "PwnBroker"
#define MyAppExeName "pwnbroker_agent.exe"

[Setup]
AppId={{6C6E9C6C-6E5F-4C6D-9A5C-4C0C7C9B6E71}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\PwnBroker
DefaultGroupName=PwnBroker
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=PwnBrokerAgentSetup
OutputDir=..\..\dist\installer
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "..\..\dist\pwnbroker_agent\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Registry]
; Same detection key the PowerShell installer writes, so existing Intune
; detection rules (Registry key exists, HKLM\SOFTWARE\PwnBroker\Agent,
; value "Version") work no matter which installer was used.
Root: HKLM; Subkey: "SOFTWARE\PwnBroker\Agent"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\PwnBroker\Agent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"
Root: HKLM; Subkey: "SOFTWARE\PwnBroker\Agent"; ValueType: string; ValueName: "Server"; ValueData: "{code:GetServerURL}"
Root: HKLM; Subkey: "SOFTWARE\PwnBroker\Agent"; ValueType: string; ValueName: "InstalledAt"; ValueData: "{code:GetNowISO}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--server ""{code:GetServerURL}"" --reg-token ""{code:GetRegToken}"" --register{code:GetNoVerifyFlag}"; WorkingDir: "{app}"; StatusMsg: "Registering agent with PwnBroker server..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "install"; WorkingDir: "{app}"; StatusMsg: "Installing Windows service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "start"; WorkingDir: "{app}"; StatusMsg: "Starting PwnBroker Agent service..."; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "stop"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "PwnBrokerStop"
Filename: "{app}\{#MyAppExeName}"; Parameters: "remove"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "PwnBrokerRemove"

[Code]
var
  ServerPage: TInputQueryWizardPage;

// Command-line params for silent/Intune installs, e.g.:
//   /SERVER=https://host /REGTOKEN=xxxx /NOVERIFYSSL=1
function ParamServer: String;
begin
  Result := ExpandConstant('{param:SERVER|}');
end;

function ParamToken: String;
begin
  Result := ExpandConstant('{param:REGTOKEN|}');
end;

function ParamNoVerifySsl: Boolean;
begin
  Result := (ExpandConstant('{param:NOVERIFYSSL|0}') <> '0');
end;

procedure InitializeWizard;
begin
  // Only prompt interactively when the caller didn't already supply
  // /SERVER on the command line (silent/Intune/GPO installs skip the UI
  // entirely — there's nothing to show).
  if ParamServer = '' then
  begin
    ServerPage := CreateInputQueryPage(wpSelectDir,
      'PwnBroker Server', 'Where should this agent register?',
      'Enter the PwnBroker server URL and the registration token from ' +
      'Threat Intel -> Agents -> Download in the web app.');
    ServerPage.Add('Server URL:', False);
    ServerPage.Add('Registration Token:', False);
    ServerPage.Values[0] := 'https://';
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (ServerPage <> nil) and (CurPageID = ServerPage.ID) then
  begin
    if (Trim(ServerPage.Values[0]) = '') or (Trim(ServerPage.Values[1]) = '') then
    begin
      MsgBox('Please enter both the server URL and registration token.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function GetServerURL(Param: String): String;
begin
  if ParamServer <> '' then
    Result := ParamServer
  else
    Result := ServerPage.Values[0];
end;

function GetRegToken(Param: String): String;
begin
  if ParamToken <> '' then
    Result := ParamToken
  else
    Result := ServerPage.Values[1];
end;

function GetNoVerifyFlag(Param: String): String;
begin
  if ParamNoVerifySsl then
    Result := ' --no-verify-ssl'
  else
    Result := '';
end;

function GetNowISO(Param: String): String;
begin
  Result := GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':');
end;
