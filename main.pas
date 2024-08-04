unit main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Winapi.TlHelp32,
  Vcl.ExtCtrls;

type
  TForm1 = class(TForm)
    dllpathBtn: TButton;
    dlgOpen: TOpenDialog;
    injector_btn: TButton;
    name_edit: TEdit;
    dll_lab: TLabel;
    name_lab: TLabel;
    Tmr1: TTimer;
    theme_btn: TButton;
    procedure dllpathBtnClick(Sender: TObject);
    procedure Tmr1Timer(Sender: TObject);
    procedure injector_btnClick(Sender: TObject);
    procedure theme_btnClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  dll_path: string;
  flag1: Boolean = False;
  flag2: Boolean = False;
  theme_flag: Integer = 1;

implementation

{$R *.dfm}

procedure TForm1.dllpathBtnClick(Sender: TObject);
var
  str, substr: string;
  pos: Integer;
begin
  dlgOpen.Filter := '文本檔案(*.dll)|*.dll';
  if dlgOpen.Execute then
  begin
    dll_path := dlgOpen.FileName + '.dll';
    if dll_path <> '' then
    begin
      MessageBox(0, '成功獲取dll文件', '提示窗口', MB_OK);

      str := dll_path;
      substr := '.dll';

      // 查找最后一个".dll"的位置
      pos := LastDelimiter('.', str);

      // 删除从这个位置到字符串结尾的所有内容
      if (pos > 0) and (pos + Length(substr) - 1 = Length(str)) then
        Delete(str, pos, Length(substr));

      dll_path := str;

      dll_lab.Caption := '成功取得dll文件路徑';
      flag1 := True;
    end;
  end;
end;

function CreateRemoteThread(
  hProcess: THandle;
  lpThreadAttributes: Pointer;
  dwStackSize: SIZE_T;
  lpStartAddress: TFNThreadStartRoutine;
  lpParameter: Pointer;
  dwCreationFlags: DWORD;
  lpThreadId: PDWORD
): THandle; stdcall; external 'kernel32.dll';

function InjectDLLIntoProcess(const ProcessName, DLLPath: string): Boolean;
var
  buff: array[0..255] of WideChar;
  ProcessID: DWORD;
  Snapshot: THandle;
  ProcessEntry: TProcessEntry32;
  ProcessHandle: THandle;
  AllocAddress: Pointer;
  Kernel32Handle: HMODULE;
  LoadLibraryAddress: Pointer;
  RemoteThreadHandle: THandle;
  Written: SIZE_T;
begin
  Result := False;
  ProcessID := 0;

  // 1. 遍历系统中的进程 找到目标进程 (CreateToolhelp32Snapshot Process32Next)
  Snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if Snapshot = INVALID_HANDLE_VALUE then
  begin
    MessageBox(0, 'CreateToolhelp32Snapshot failed', 'Error', MB_OK);
    Exit;
  end;

  ProcessEntry.dwSize := SizeOf(TProcessEntry32);
  if Process32First(Snapshot, ProcessEntry) then
  begin
    repeat
      if CompareText(ProcessEntry.szExeFile, ProcessName) = 0 then
      begin
        ProcessID := ProcessEntry.th32ProcessID;
        Break;
      end;
    until not Process32Next(Snapshot, ProcessEntry);
  end;
  CloseHandle(Snapshot);

  if ProcessID = 0 then
  begin
    MessageBox(0, '沒有找到進程ID', 'Error', MB_OK);
    Exit;
  end;

  // 2. 打开程序进程 获取HANDLE (OpenProcess)
  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, False, ProcessID);
  if ProcessHandle = 0 then
  begin
    MessageBox(0, '打開進程失敗', 'Error', MB_OK);
    Exit;
  end;

  // 3. 在目标程序进程中为DLL文件分配内存空间 (VirtualAllocEx)
  AllocAddress := VirtualAllocEx(ProcessHandle, nil, (Length(DLLPath) + 1) * SizeOf(Char), MEM_COMMIT, PAGE_READWRITE);
  if AllocAddress = nil then
  begin
    MessageBox(0, '分配內存空間失敗', 'Error', MB_OK);
    CloseHandle(ProcessHandle);
    Exit;
  end;

   // 4. 把DLL文件写入目标进程的内存空间 (WriteProcessMemory)
  if not WriteProcessMemory(ProcessHandle, AllocAddress, PChar(DLLPath), (Length(DLLPath) + 1) * SizeOf(Char), Written) then
  begin
    MessageBox(0, '寫入目標進程的內存空間失敗', 'Error', MB_OK);
    VirtualFreeEx(ProcessHandle, AllocAddress, 0, MEM_RELEASE);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  // 5. 从KERNEL32.DLL中获取LoadLibraryA函数地址 (GetModuleHandle GetProcAddress)
  Kernel32Handle := GetModuleHandle('kernel32.dll');
  LoadLibraryAddress := GetProcAddress(Kernel32Handle, 'LoadLibraryW');
  if LoadLibraryAddress = nil then
  begin
    MessageBox(0, '獲取LoadLibraryA函數地址失敗', 'Error', MB_OK);
    VirtualFreeEx(ProcessHandle, AllocAddress, 0, MEM_RELEASE);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  // 6. 在目标程序中启动内存中指定文件名路径的DLL (CreateRemoteThread)
  // 也就是调用DLL中的DLLMain (以DLL_PROCESS_ATTACH为参数)
  RemoteThreadHandle := CreateRemoteThread(ProcessHandle, nil, 0, TFNThreadStartRoutine(LoadLibraryAddress), AllocAddress, 0, nil);
  if RemoteThreadHandle = 0 then
  begin
    MessageBox(0, '注入失敗', 'Error', MB_OK);
    VirtualFreeEx(ProcessHandle, AllocAddress, 0, MEM_RELEASE);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  // Wait for the remote thread to complete
  WaitForSingleObject(RemoteThreadHandle, INFINITE);

  // Clean up
  CloseHandle(RemoteThreadHandle);
  VirtualFreeEx(ProcessHandle, AllocAddress, 0, MEM_RELEASE);
  CloseHandle(ProcessHandle);

  Result := True;
end;

procedure TForm1.injector_btnClick(Sender: TObject);
begin
  if (flag1 = True) and (flag2 = True) then
  begin
    InjectDLLIntoProcess(name_edit.Text, dll_path);
  end;

  if flag1 = False then
  begin
    MessageBox(0, '請先獲取程序名稱', '提示窗口', MB_OK);
  end;

  if flag2 = False then
  begin
    MessageBox(0, '請先獲取dll文件路徑', '提示窗口', MB_OK);
  end;

end;

procedure TForm1.theme_btnClick(Sender: TObject);
begin
  if theme_flag < 5 then
  begin
    theme_flag := theme_flag + 1;
  end
  else
  begin
    theme_flag := 1;
  end;


  if theme_flag = 1 then
  begin
    Form1.StyleName := 'Windows11 Impressive Dark SE';
  end
  else if theme_flag = 2 then
  begin
    Form1.StyleName := 'Tablet Dark';
  end
  else if theme_flag = 3 then
  begin
    Form1.StyleName := 'Sky';
  end
  else if theme_flag = 4 then
  begin
    Form1.StyleName := 'Windows10 Dark';
  end
  else if theme_flag = 5 then
  begin
    Form1.StyleName := 'Cyan Dusk';
  end;
end;

procedure TForm1.Tmr1Timer(Sender: TObject);
var
  str, substr: string;
  pos: Integer;
begin
  str := name_edit.Text;
  substr := '.exe';
  pos := AnsiPos(substr, str);

  if pos > 0 then
  begin
    name_lab.Caption := '成功獲取程序名稱';
    flag2 := True;
  end
  else
  begin
    name_lab.Caption := '尚未獲取程序名稱';
    flag2 := False;
  end;
end;

end.
