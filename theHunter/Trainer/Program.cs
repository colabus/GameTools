using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

static class Program {
 [STAThread] static void Main(string[] args) {
  if(args.Contains("--self-test")){ Engine.SelfTest(); return; }
  if(args.Contains("--diagnose")){try{Console.WriteLine(Engine.Diagnose());}catch(Exception ex){Console.WriteLine("Inspection unavailable: "+ex.Message);Environment.ExitCode=1;}return; }
  if(args.Length==2&&args[0]=="--verify-file"){try{Console.WriteLine(Engine.VerifyFile(args[1]));}catch(Exception ex){Console.WriteLine(ex.Message);Environment.ExitCode=1;}return;}
  Application.EnableVisualStyles(); Application.Run(new Window());
 }
}
sealed class Window : Form {
 readonly NumericUpDown factor=new NumericUpDown { Minimum=1, Maximum=20, DecimalPlaces=2, Increment=.25m, Value=2, Width=100 };
 readonly TextBox status=new TextBox { Multiline=true, ReadOnly=true, ScrollBars=ScrollBars.Vertical, Width=600, Height=250 };
 readonly Engine engine=new Engine();
 readonly Engine animals=new Engine(); readonly CheckBox relaxed=new CheckBox {Text="Always Relaxed Animals",AutoSize=true}; bool updating;
 string lastError="";
 public Window(){ Text="theHunter: COTW Trainer by colabus"; using(var iconStream=typeof(Window).Assembly.GetManifestResourceStream("TrainerIcon")){Icon=new System.Drawing.Icon(iconStream);} Width=650; Height=490; FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false;
  var layout=new FlowLayoutPanel { Dock=DockStyle.Fill, Padding=new Padding(16), FlowDirection=FlowDirection.TopDown, WrapContents=false };
  layout.Controls.Add(new Label { Text="Speed factor (baseline × factor)", AutoSize=true }); layout.Controls.Add(factor);
  var row=new FlowLayoutPanel { Width=600, Height=40 }; var apply=new Button {Text="Apply"}; var disable=new Button {Text="Disable"}; var inspect=new Button {Text="Inspect",Width=100}; row.Controls.Add(apply); row.Controls.Add(disable); row.Controls.Add(inspect); layout.Controls.Add(row);
  layout.Controls.Add(new Label {Text="Baseline: 2 / 0.5 / 0.25. Original trainer: 5× / 4× / 4×.",AutoSize=true}); layout.Controls.Add(relaxed); layout.Controls.Add(status); Controls.Add(layout);
  relaxed.CheckedChanged+=(s,e)=>{if(updating)return; try{animals.SetRelaxed(relaxed.Checked);lastError="";status.Text=animals.Status;}catch(Exception ex){lastError=ex.Message;status.Text=ex.Message;updating=true;relaxed.Checked=animals.RelaxedOwned;updating=false;}};
  var timer=new System.Windows.Forms.Timer {Interval=1000}; timer.Tick+=(s,e)=>{engine.ResetExited();if(animals.ResetExited()){updating=true;relaxed.Checked=false;updating=false;status.Text="Game exited. Always Relaxed Animals is off; enable again after restart.";}}; timer.Start();
  status.Text="No game memory has been changed.";
  apply.Click+=(s,e)=> { if(MessageBox.Show(this,"Apply this factor to the running game's memory? The game will pause briefly during the patch.","Approve game-memory write",MessageBoxButtons.OKCancel)!=DialogResult.OK)return; Run(()=>engine.Apply((float)factor.Value)); };
  disable.Click+=(s,e)=>Run(()=>engine.Disable());
  inspect.Click+=(s,e)=>{try{status.Text=engine.Inspect()+animals.AnimalOwnershipReport()+ (lastError.Length==0?"":"\r\nLAST OPERATION ERROR:\r\n"+lastError);}catch(Exception ex){status.Text=ex.Message;}};
  FormClosing+=(s,e)=>{try{animals.SetRelaxed(false);animals.Dispose();engine.Disable();engine.Dispose();}catch(Exception ex){e.Cancel=true;status.Text="Disable failed; keep this window open: "+ex.Message;}};
 }
 void Run(Action action){try{action();lastError="";status.Text=engine.Status;}catch(Exception ex){lastError=ex.Message;status.Text=ex.Message;}}
}
sealed class Engine : IDisposable {
 static string FileHash(string path){using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");}
 static readonly byte[] SpeedSignature=Parse("48 8D 8D 30 03 00 00 BB 02 00 00 00 8B D3 0F 10 00 0F 11 01 0F 10 48 10 0F 11 49 10");
 static readonly byte[] AnimalSignature=Parse("F3 0F 59 C7 F3 0F 58 C1 F3 0F 5F C6 F3 0F 5D 83");
 int Hook, RelaxedRva, Cave, Control;
 sealed class Section {public int Rva,Size,Offset,RawSize;}
 List<Section> sections;
 static byte[] Parse(string value){return value.Split(' ').Select(x=>Convert.ToByte(x,16)).ToArray();}
 static List<int> Matches(byte[] bytes,byte[] signature){var hits=new List<int>();for(int i=0;i<=bytes.Length-signature.Length;i++){if(bytes[i]!=signature[0])continue;int j=1;while(j<signature.Length&&bytes[i+j]==signature[j])j++;if(j==signature.Length)hits.Add(i);}return hits;}
 static int Unique(List<int> hits,string feature){if(hits.Count!=1)throw new IOException(feature+": expected exactly one AOB signature match; found "+hits.Count+". No patch was applied.");return hits[0];}
 static List<Section> Sections(byte[] raw,out int tableEnd,out int headers){
  if(raw.Length<64||BitConverter.ToUInt16(raw,0)!=0x5a4d)throw new IOException("Invalid executable header.");
  int pe=BitConverter.ToInt32(raw,0x3c);
  if(pe<0||pe>raw.Length-264||BitConverter.ToUInt32(raw,pe)!=0x4550||BitConverter.ToUInt16(raw,pe+4)!=0x8664||BitConverter.ToUInt16(raw,pe+24)!=0x20b)throw new IOException("Expected an AMD64 PE executable.");
  int count=BitConverter.ToUInt16(raw,pe+6),table=pe+24+BitConverter.ToUInt16(raw,pe+20);
  tableEnd=checked(table+count*40);headers=BitConverter.ToInt32(raw,pe+24+60);
  if(tableEnd>raw.Length||headers<tableEnd||headers>raw.Length)throw new IOException("Invalid section table.");
  var result=new List<Section>();
  for(int i=0;i<count;i++){int t=table+i*40;if((BitConverter.ToUInt32(raw,t+36)&0x20000000)==0)continue;
   var v=new Section {Rva=BitConverter.ToInt32(raw,t+12),Size=BitConverter.ToInt32(raw,t+8),Offset=BitConverter.ToInt32(raw,t+20),RawSize=BitConverter.ToInt32(raw,t+16)};
   if(v.Rva<0||v.Size<=0||v.Offset<0||v.RawSize<0||(long)v.Offset+v.RawSize>raw.Length)throw new IOException("Invalid executable section.");result.Add(v);
  }if(result.Count==0)throw new IOException("No executable sections.");return result;
 }
 void LoadImage(){var m=process.MainModule;if(!string.Equals(m.ModuleName,"theHunterCotW_F.exe",StringComparison.OrdinalIgnoreCase))throw new IOException("Unexpected game module.");
  var raw=File.ReadAllBytes(m.FileName);int end,headers;sections=Sections(raw,out end,out headers);
  foreach(var v in sections)if((long)v.Rva+v.Size>m.ModuleMemorySize)throw new IOException("Executable section exceeds game module.");
  Control=0;Cave=0;for(int i=end;i<=headers-16;i++){if(raw.Skip(i).Take(16).All(b=>b==0)){Control=i;Cave=i+2;break;}}
 }
 int Scan(byte[] signature,int offset,string feature){
  var hits=new List<int>();foreach(var v in sections){for(int pos=0;pos<v.Size;pos+=65536){int length=Math.Min(65536+signature.Length-1,v.Size-pos);var bytes=Read(Add(module,(long)v.Rva+pos),length);
   foreach(int hit in Matches(bytes,signature))if(hit<65536)hits.Add(checked(v.Rva+pos+hit));}}
  int match=Unique(hits,feature),target=checked(match+offset);
  if(!sections.Any(v=>target>=v.Rva&&(long)target+8<=(long)v.Rva+v.Size))throw new IOException(feature+": patch lies outside executable section.");return target;
 }
 static int DiskScan(byte[] raw,List<Section> list,byte[] signature,int offset,string feature){var hits=new List<int>();foreach(var v in list)foreach(int hit in Matches(raw.Skip(v.Offset).Take(v.RawSize).ToArray(),signature))hits.Add(checked(v.Rva+hit));return checked(Unique(hits,feature)+offset);}
 public static string VerifyFile(string path){var raw=File.ReadAllBytes(path);int end,headers;var list=Sections(raw,out end,out headers);return "READ-ONLY FILE AOB verification\r\nSHA-256: "+FileHash(path)+"\r\nSpeed hook RVA: 0x"+DiskScan(raw,list,SpeedSignature,0x1c,"Super Speed").ToString("X")+"\r\nAnimal patch RVA: 0x"+DiskScan(raw,list,AnimalSignature,0x0c,"Animals").ToString("X");}
 public string AnimalOwnershipReport(){
  ResetExited();
  return "\r\nAlways Relaxed Animals owned by this window: "+relaxedOwned+
   (relaxedOwned?"; stored RVA 0x"+RelaxedRva.ToString("X")+"; address 0x"+Add(module,RelaxedRva).ToInt64().ToString("X")+"; live bytes: "+Hex(Read(Add(module,RelaxedRva),8))+"; owned live bytes match: "+Read(Add(module,RelaxedRva),8).SequenceEqual(RelaxedPatch):"")+
   "\r\n";
 }
 static void CompatibilitySelfTest(){
  foreach(var signature in new[]{SpeedSignature,AnimalSignature}){
   var bytes=new byte[70000];Array.Copy(signature,0,bytes,65530,signature.Length);
   if(Unique(Matches(bytes,signature),"test")!=65530)throw new Exception("Unique scan failed.");
   Array.Copy(signature,0,bytes,10,signature.Length);bool refused=false;try{Unique(Matches(bytes,signature),"test");}catch(IOException){refused=true;}if(!refused)throw new Exception("Duplicate accepted.");
   refused=false;try{Unique(Matches(new byte[128],signature),"test");}catch(IOException){refused=true;}if(!refused)throw new Exception("Missing accepted.");
  }
  Console.WriteLine("PASS: unique AOB matching, duplicate and missing match refusal.");
  var e=new Engine();e.handle=new IntPtr(-1);var memory=VirtualAllocEx(e.handle,IntPtr.Zero,(UIntPtr)196608,0x3000,4);Check(memory!=IntPtr.Zero);
  try{
   e.module=Add(memory,-0x1000);e.sections=new List<Section>{new Section {Rva=0x1000,Size=196608}};
   foreach(var signature in new[]{SpeedSignature,AnimalSignature}){
    e.Write(memory,new byte[196608]);e.Write(Add(memory,65530),signature);int delta=signature==SpeedSignature?0x1c:0x0c;
    if(e.Scan(signature,delta,"test")!=0x1000+65530+delta)throw new Exception("Chunk boundary or relocated module scan failed.");
    e.Write(Add(memory,131070),signature);bool refused=false;try{e.Scan(signature,delta,"test");}catch(IOException){refused=true;}if(!refused)throw new Exception("Chunk duplicate accepted.");
    e.Write(memory,new byte[196608]);refused=false;try{e.Scan(signature,delta,"test");}catch(IOException){refused=true;}if(!refused)throw new Exception("Chunk absent match accepted.");
   }
   e.sections[0].Size=4096;e.Write(Add(memory,8192),SpeedSignature);bool outside=false;try{e.Scan(SpeedSignature,0x1c,"test");}catch(IOException){outside=true;}if(!outside)throw new Exception("Match outside scan section accepted.");
   Console.WriteLine("PASS: process-memory AOB scan across chunks, signature offsets, relocated base, duplicate/absent refusal, section bounds.");
  }finally{Check(VirtualFreeEx(e.handle,memory,UIntPtr.Zero,0x8000));}
 }
 static readonly byte[] RelaxedOriginal={0xF3,0x0F,0x5D,0x83,0xB4,0x41,0x00,0x00};
 static readonly byte[] RelaxedPatch={0x0F,0x57,0xC0,0x90,0x90,0x90,0x90,0x90};
 bool relaxedOwned; public bool RelaxedOwned {get{return relaxedOwned;}}
 const int Capacity=1024;
 static readonly byte[] Original={0x0f,0x10,0x40,0x20,0x0f,0x11,0x41,0x20};
 IntPtr handle, module, code, data; Process process; byte[] savedCave, savedControl, patch, cavePatch; float current; bool enabled; uint caveProtection; bool caveExecutable;
 public string Status="Disabled.";
 static IntPtr Add(IntPtr p,long n){return new IntPtr(p.ToInt64()+n);}
 static void Check(bool ok,string operation="Windows operation"){if(!ok){int error=Marshal.GetLastWin32Error();throw new Win32Exception(error,operation+" failed (Windows error "+error+"): "+new Win32Exception(error).Message);}}
 byte[] Read(IntPtr p,int n){var b=new byte[n];IntPtr done;Check(ReadProcessMemory(handle,p,b,n,out done),"Read memory at 0x"+p.ToInt64().ToString("X"));if(done.ToInt64()!=n)throw new IOException("Incomplete memory read.");return b;}
 void Write(IntPtr p,byte[] b){IntPtr done;Check(WriteProcessMemory(handle,p,b,b.Length,out done),"Write memory at 0x"+p.ToInt64().ToString("X"));if(done.ToInt64()!=b.Length)throw new IOException("Incomplete memory write.");}
 void ProtectedWrite(IntPtr p,byte[] b){uint old;Check(VirtualProtectEx(handle,p,(UIntPtr)b.Length,0x40,out old),"Set temporary write protection at 0x"+p.ToInt64().ToString("X"));try{Write(p,b);Check(FlushInstructionCache(handle,p,(UIntPtr)b.Length),"Flush instruction cache at 0x"+p.ToInt64().ToString("X"));}finally{uint ignored;Check(VirtualProtectEx(handle,p,(UIntPtr)b.Length,old,out ignored),"Restore memory protection at 0x"+p.ToInt64().ToString("X"));}}
 static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-"," ");}
 void Expect(IntPtr p,byte[] b){var actual=Read(p,b.Length);if(!actual.SequenceEqual(b))throw new InvalidOperationException("Mismatch at module RVA 0x"+(p.ToInt64()-module.ToInt64()).ToString("X")+".\r\nExpected: "+Hex(b)+"\r\nActual: "+Hex(actual)+"\r\nNo unknown patch will be overwritten. Inspect for details. A disabled original trainer may leave its hook installed; close it and restart the game.");}
 void RestoreKnown(IntPtr address,byte[] owned,byte[] original){var actual=Read(address,original.Length);if(actual.SequenceEqual(original))return;if(!actual.SequenceEqual(owned))throw new IOException("Rollback refused unknown bytes at 0x"+address.ToInt64().ToString("X")+". Keep the trainer open or restart the game; allocations have been retained.");ProtectedWrite(address,original);}
 public static string Diagnose(){var e=new Engine();try{e.Connect(0x410);e.LoadImage();var report=new StringBuilder();
  report.AppendLine("READ-ONLY INSPECTION — no writes or thread suspension.");var path=e.process.MainModule.FileName;
  report.AppendLine("Executable: "+path);report.AppendLine("PID: "+e.process.Id+"; module base: 0x"+e.module.ToInt64().ToString("X"));report.AppendLine("SHA-256 (informational): "+FileHash(path));
  var version=FileVersionInfo.GetVersionInfo(path);report.AppendLine("File version: "+version.FileVersion+"; product version: "+version.ProductVersion);
  foreach(bool animal in new[]{false,true}){string feature=animal?"Always Relaxed Animals":"Super Speed";try{
   int rva=e.Scan(animal?AnimalSignature:SpeedSignature,animal?0x0c:0x1c,feature);var bytes=e.Read(Add(e.module,rva),8);
   report.AppendLine(feature+" unique live signature; RVA 0x"+rva.ToString("X")+"; address 0x"+Add(e.module,rva).ToInt64().ToString("X"));report.AppendLine("Original: "+Hex(animal?RelaxedOriginal:Original));report.AppendLine("Live: "+Hex(bytes));report.AppendLine("Original bytes match: "+bytes.SequenceEqual(animal?RelaxedOriginal:Original));
  }catch(Exception ex){report.AppendLine(feature+": "+ex.Message);if(animal)report.AppendLine("An enabled animal patch replaces part of its signature; use the owning window's stored address to disable.");}}
  return report.ToString();
 }finally{e.Dispose();if(e.process!=null)e.process.Dispose();}}
 public string Inspect(){var report=Diagnose();if(!enabled)return report+"\r\nThis window does not own an enabled patch. It cannot remove another instance's patch.\r\n";
  report+="\r\nThis window OWNS a patch: factor "+current+"; stub 0x"+code.ToInt64().ToString("X")+"; data 0x"+data.ToInt64().ToString("X")+".\r\n";
  report+="Owned live hook matches: "+Read(Add(module,Hook),8).SequenceEqual(patch)+"; owned cave matches: "+Read(Add(module,Cave),14).SequenceEqual(cavePatch)+".\r\n";
  int count=BitConverter.ToInt32(Read(Add(data,12),4),0);report+="Tracked sources: "+count+" (read while game is running; snapshot may change).\r\n";return report;
 }
 void Connect(int access){ResetExited();if(handle!=IntPtr.Zero)return;var ps=Process.GetProcessesByName("theHunterCotW_F");if(ps.Length!=1){foreach(var p in ps)p.Dispose();throw new InvalidOperationException("Start exactly one theHunterCotW_F.exe instance.");}
  process=ps[0];try{module=process.MainModule.BaseAddress;handle=OpenProcess(access,false,process.Id);Check(handle!=IntPtr.Zero,"Open game process");}catch{Dispose();process.Dispose();process=null;throw;}}
 void Attach(){Connect(0x438);if(enabled){if(Scan(SpeedSignature,0x1c,"Super Speed")!=Hook)throw new IOException("Super Speed signature moved in the attached process. Refusing factor update.");return;}
  try{LoadImage();Hook=Scan(SpeedSignature,0x1c,"Super Speed");if(Cave==0)throw new IOException("No safe unused PE header padding for the existing speed trampoline.");
   Expect(Add(module,Hook),Original);savedCave=Read(Add(module,Cave),14);savedControl=Read(Add(module,Control),2);
   if(savedCave.Concat(savedControl).Any(x=>x!=0))throw new IOException("Speed trampoline padding is occupied. No third-party patch will be overwritten.");
  }catch{Dispose();throw;}
 }
 public void Apply(float factor){if(float.IsNaN(factor)||factor<1||factor>20)throw new ArgumentOutOfRangeException("factor");Attach();
  using(var stop=Freeze()){
   if(enabled){Expect(Add(module,Hook),patch);Expect(Add(module,Cave),cavePatch);Expect(Add(module,Control),new byte[]{1,0});RestoreSources();SetValues(factor);current=factor;Status="Applied "+factor+"×.";return;}
   Expect(Add(module,Hook),Original);Expect(Add(module,Cave),savedCave);Expect(Add(module,Control),savedControl);
   try{data=VirtualAllocEx(handle,IntPtr.Zero,(UIntPtr)(20+Capacity*8),0x3000,4);Check(data!=IntPtr.Zero);code=VirtualAllocEx(handle,IntPtr.Zero,(UIntPtr)4096,0x3000,4);Check(code!=IntPtr.Zero);
    SetValues(factor);var stub=BuildStub(data);Write(code,stub);uint old;Check(VirtualProtectEx(handle,code,(UIntPtr)4096,0x20,out old));Check(FlushInstructionCache(handle,code,(UIntPtr)stub.Length));
    cavePatch=new byte[14];cavePatch[0]=0xff;cavePatch[1]=0x25;Array.Copy(BitConverter.GetBytes(code.ToInt64()),0,cavePatch,6,8);
    patch=new byte[]{0xe9,0,0,0,0,0x90,0x90,0x90};Array.Copy(BitConverter.GetBytes(Cave-Hook-5),0,patch,1,4);
    Check(VirtualProtectEx(handle,Add(module,Cave),(UIntPtr)14,0x20,out caveProtection));caveExecutable=true;
    ProtectedWrite(Add(module,Cave),cavePatch);ProtectedWrite(Add(module,Control),new byte[]{1,0});ProtectedWrite(Add(module,Hook),patch);enabled=true;current=factor;Status="Applied "+factor+"×. Disable or close this window to restore.";
   }catch{ // Threads remain stopped throughout rollback. Never overwrite unknown bytes or free reachable code.
    enabled=true;
    RestoreKnown(Add(module,Hook),patch,Original);RestoreKnown(Add(module,Cave),cavePatch,savedCave);RestoreKnown(Add(module,Control),new byte[]{1,0},savedControl);RestoreCaveProtection();enabled=false;Free();throw;
   }
  }
 }
 void SetValues(float f){Write(data,BitConverter.GetBytes(2*f).Concat(BitConverter.GetBytes(.5f*f)).Concat(BitConverter.GetBytes(.25f*f)).ToArray());}
 void RestoreSources(){int count=BitConverter.ToInt32(Read(Add(data,12),4),0);if(count<0||count>Capacity)throw new IOException("Invalid source registry.");
  for(int i=0;i<count;i++){var p=new IntPtr(BitConverter.ToInt64(Read(Add(data,16+i*8),8),0));for(int j=0;j<3;j++){int off=0x20+j*8;float baseline=j==0?2:j==1?.5f:.25f;var addr=Add(p,off);byte[] now;try{now=Read(addr,4);}catch(Win32Exception){continue;}if(now.SequenceEqual(BitConverter.GetBytes(baseline*current)))ProtectedWrite(addr,BitConverter.GetBytes(baseline));}}
  Write(Add(data,12),new byte[4]);
 }
 public void Disable(){if(!enabled){Status="This window has no enabled patch to disable. If another instance applied speed, use Disable in that window.";return;}if(process.HasExited){enabled=false;code=IntPtr.Zero;data=IntPtr.Zero;caveExecutable=false;Dispose();Status="Game exited; patch no longer exists.";return;}
  using(var stop=Freeze()){Expect(Add(module,Hook),patch);Expect(Add(module,Cave),cavePatch);Expect(Add(module,Control),new byte[]{1,0});RestoreSources();ProtectedWrite(Add(module,Hook),Original);ProtectedWrite(Add(module,Cave),savedCave);ProtectedWrite(Add(module,Control),savedControl);RestoreCaveProtection();enabled=false;Free();Status="Disabled; original hook, padding and tracked baseline values restored.";}}
 public bool ResetExited(){
  if(process==null||!process.HasExited)return false;
  enabled=false;relaxedOwned=false;code=IntPtr.Zero;data=IntPtr.Zero;caveExecutable=false;
  Dispose();process.Dispose();process=null;module=IntPtr.Zero;Hook=RelaxedRva=Cave=Control=0;sections=null;return true;
 }
 void AttachRelaxed(){Connect(0x438);if(relaxedOwned)return;try{LoadImage();RelaxedRva=Scan(AnimalSignature,0x0c,"Always Relaxed Animals");}catch{Dispose();throw;}}
 public void SetRelaxed(bool on){
  ResetExited();
  if(!on&&!relaxedOwned){Status="Always Relaxed Animals is off. No owned patch to remove.";return;}
  AttachRelaxed();
  using(var stop=Freeze()){
   var address=Add(module,RelaxedRva);
   if(on&&relaxedOwned){Expect(address,RelaxedPatch);Status="Always Relaxed Animals is on.";return;}
   Expect(address,on?RelaxedOriginal:RelaxedPatch);
   // Record ownership before writing so a cache/protection failure can still be recovered.
   if(on)relaxedOwned=true;
   try{ProtectedWrite(address,on?RelaxedPatch:RelaxedOriginal);Expect(address,on?RelaxedPatch:RelaxedOriginal);relaxedOwned=on;}
   catch{
    // A complete original signature means no patch remains. Never overwrite partial/unknown bytes.
    try{if(Read(address,8).SequenceEqual(RelaxedOriginal))relaxedOwned=false;}catch{}
    throw;
   }
   Status="Always Relaxed Animals is "+(on?"on.":"off; original bytes restored.");
  }
 }
 static void RelaxedSelfTest(){
  var e=new Engine();e.handle=new IntPtr(-1);
  var memory=VirtualAllocEx(e.handle,IntPtr.Zero,(UIntPtr)4096,0x3000,4);Check(memory!=IntPtr.Zero);
  e.RelaxedRva=0x120;e.module=Add(memory,-e.RelaxedRva);
  try{
   e.Write(memory,RelaxedOriginal);e.Expect(Add(e.module,e.RelaxedRva),RelaxedOriginal);
   e.ProtectedWrite(memory,RelaxedPatch);e.Expect(memory,RelaxedPatch);
   e.RestoreKnown(memory,RelaxedPatch,RelaxedOriginal);e.Expect(memory,RelaxedOriginal);
   e.RestoreKnown(memory,RelaxedPatch,RelaxedOriginal);
   var unknown=new byte[]{1,2,3,4,5,6,7,8};e.Write(memory,unknown);
   foreach(var signature in new[]{RelaxedOriginal,RelaxedPatch}){
    bool refused=false;try{e.Expect(memory,signature);}catch(InvalidOperationException){refused=true;}
    if(!refused||!e.Read(memory,8).SequenceEqual(unknown))throw new Exception("Animal mismatch refusal failed.");
   }
   bool rollbackRefused=false;try{e.RestoreKnown(memory,RelaxedPatch,RelaxedOriginal);}catch(IOException){rollbackRefused=true;}
   if(!rollbackRefused||!e.Read(memory,8).SequenceEqual(unknown))throw new Exception("Rollback overwrote unknown bytes.");
   Console.WriteLine("PASS: animal RVA calculation, enable/restore bytes, protected writes/cache flush, mismatched signature refusal.");
  }finally{Check(VirtualFreeEx(e.handle,memory,UIntPtr.Zero,0x8000));}
 }
 Frozen Freeze(){return RetrySnapshot(()=>new Frozen(process,code,code==IntPtr.Zero?0:4096,module,Hook,Cave,RelaxedRva),ms=>Thread.Sleep(ms));}
 sealed class SnapshotBusy : Exception {public SnapshotBusy(string reason):base(reason){}}
 static T RetrySnapshot<T>(Func<T> attempt,Action<int> delay){for(int n=0;;n++){try{return attempt();}catch(SnapshotBusy ex){if(n==24)throw new InvalidOperationException("Could not obtain a stable thread snapshot after 25 attempts. No patch changes were started. "+ex.Message);delay(10);}}}
 void RestoreCaveProtection(){if(caveExecutable){uint ignored;Check(VirtualProtectEx(handle,Add(module,Cave),(UIntPtr)14,caveProtection,out ignored));caveExecutable=false;}}
 void Free(){if(code!=IntPtr.Zero){Check(VirtualFreeEx(handle,code,UIntPtr.Zero,0x8000));code=IntPtr.Zero;}if(data!=IntPtr.Zero){Check(VirtualFreeEx(handle,data,UIntPtr.Zero,0x8000));data=IntPtr.Zero;}}
 public void Dispose(){if(enabled||relaxedOwned)throw new InvalidOperationException("Disable before disposing.");if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
 // Serialize access to the pointer registry without changing any game flags/registers.
 byte[] BuildStub(IntPtr d){var a=new Assembler();a.Bytes(0x9c,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53);a.Bytes(0x49,0xba);a.Long(d.ToInt64());
  // Lock is stored after the pointer registry (separate from count).
  a.Label("lock");a.Bytes(0x41,0xbb,1,0,0,0,0x45,0x87,0x9a);a.Int(16+Capacity*8);a.Bytes(0x45,0x85,0xdb);a.Jump(0x85,"lock");
  a.Bytes(0x45,0x8b,0x42,0x0c,0x45,0x31,0xc9);a.Label("scan");a.Bytes(0x45,0x39,0xc1);a.Jump(0x83,"new");a.Bytes(0x4b,0x3b,0x44,0xca,0x10);a.Jump(0x84,"write");a.Bytes(0x41,0xff,0xc1);a.Jump("scan");
  a.Label("new");a.Bytes(0x41,0x81,0xf8);a.Int(Capacity);a.Jump(0x83,"unlock");
  foreach(var pair in new[]{new[]{0x20,0x40000000},new[]{0x28,0x3f000000},new[]{0x30,0x3e800000}}){a.Bytes(0x81,0x78,(byte)pair[0]);a.Int(pair[1]);a.Jump(0x85,"unlock");}
  a.Bytes(0x4b,0x89,0x44,0xc2,0x10,0x41,0xff,0x42,0x0c);a.Label("write");
  for(int j=0;j<3;j++)a.Bytes(0x41,0x8b,0x52,(byte)(j*4),0x89,0x50,(byte)(0x20+j*8));
  a.Label("unlock");a.Bytes(0x41,0xc7,0x82);a.Int(16+Capacity*8);a.Int(0);a.Bytes(0x41,0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5a,0x9d);a.Bytes(Original);a.Bytes(0xff,0x25,0,0,0,0);a.Long(module.ToInt64()+Hook+8);return a.Finish();}
 [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void TestHook(IntPtr source,IntPtr destination);
 public static void SelfTest(){CompatibilitySelfTest();RelaxedSelfTest();int tries=0;int retryResult=RetrySnapshot(()=>{if(++tries<3)throw new SnapshotBusy("test exit race");return 42;},ms=>{});if(tries!=3||retryResult!=42)throw new Exception("Thread snapshot retry test failed.");tries=0;try{RetrySnapshot<int>(()=>{tries++;throw new Win32Exception(5);},ms=>{});throw new Exception("Access-denied failure was hidden.");}catch(Win32Exception){if(tries!=1)throw new Exception("Persistent permissions were retried.");}tries=0;try{RetrySnapshot<int>(()=>{tries++;throw new SnapshotBusy("always busy");},ms=>{});throw new Exception("Unbounded retry.");}catch(InvalidOperationException){if(tries!=25)throw new Exception("Retry bound failed.");}Console.WriteLine("PASS: thread snapshot retry, bounded attempts, persistent permission failure propagation.");var e=new Engine();e.module=new IntPtr(0x140000000);e.Hook=0x234560;var b=e.BuildStub(new IntPtr(0x180000000));if(b.Length>=4096||!b.Skip(b.Length-22).Take(8).SequenceEqual(Original)||BitConverter.ToInt64(b,b.Length-8)!=0x140234568)throw new Exception("Stub test failed.");
  e.handle=new IntPtr(-1);e.data=VirtualAllocEx(e.handle,IntPtr.Zero,(UIntPtr)12288,0x3000,4);e.code=VirtualAllocEx(e.handle,IntPtr.Zero,(UIntPtr)4096,0x3000,4);var memory=VirtualAllocEx(e.handle,IntPtr.Zero,(UIntPtr)4096,0x3000,4);Check(e.data!=IntPtr.Zero&&e.code!=IntPtr.Zero&&memory!=IntPtr.Zero);
  try{var native=e.BuildStub(e.data); // Adapter maps Windows argument registers to the intercepted instruction's registers.
   e.Write(e.code,new byte[]{0x48,0x89,0xc8,0x48,0x89,0xd1}.Concat(native.Take(native.Length-14)).Concat(new byte[]{0xc3}).ToArray());uint old;Check(VirtualProtectEx(e.handle,e.code,(UIntPtr)4096,0x20,out old));Check(FlushInstructionCache(e.handle,e.code,(UIntPtr)4096));
   var run=(TestHook)Marshal.GetDelegateForFunctionPointer(e.code,typeof(TestHook));var dst=Add(memory,128);
   Action<float> init=(v)=>{e.Write(Add(memory,0x20),BitConverter.GetBytes(v));e.Write(Add(memory,0x28),BitConverter.GetBytes(.5f));e.Write(Add(memory,0x30),BitConverter.GetBytes(.25f));};
   Action<float> assert=(f)=>{foreach(int j in new[]{0,1,2}){float baseline=j==0?2:j==1?.5f:.25f;if(!e.Read(Add(memory,0x20+8*j),4).SequenceEqual(BitConverter.GetBytes(baseline*f)))throw new Exception("Incorrect scaled value at field "+j+": expected "+(baseline*f)+", actual "+BitConverter.ToSingle(e.Read(Add(memory,0x20+8*j),4),0));}};
   init(2);e.SetValues(3);e.current=3;run(memory,dst);assert(3);run(memory,dst);assert(3);if(BitConverter.ToInt32(e.Read(Add(e.data,12),4),0)!=1)throw new Exception("Duplicate registry entry.");if(!e.Read(Add(memory,0x20),16).SequenceEqual(e.Read(Add(dst,0x20),16)))throw new Exception("Original copy differs.");
   e.RestoreSources();assert(1);e.SetValues(5);e.current=5;run(memory,dst);assert(5);e.RestoreSources();assert(1);
   init(7);run(memory,dst);if(BitConverter.ToInt32(e.Read(Add(e.data,12),4),0)!=0||BitConverter.ToSingle(e.Read(Add(memory,0x20),4),0)!=7)throw new Exception("Unknown baseline modified.");
   init(2);e.Write(Add(e.data,16),new byte[Capacity*8]);e.Write(Add(e.data,12),BitConverter.GetBytes(Capacity));run(memory,dst);assert(1);
   Console.WriteLine("PASS: native x64 hook execution; scaled values; original 16-byte copy; repeated application; unique source tracking; restoration; factor updates; unknown baseline refusal; full registry refusal; return address/fixups.");
  }finally{e.Free();Check(VirtualFreeEx(e.handle,memory,UIntPtr.Zero,0x8000));}
 }
 sealed class Frozen : IDisposable {
  static void ThreadFailure(Process p,int id,int error,string operation){p.Refresh();bool stillListed=p.Threads.Cast<ProcessThread>().Any(t=>t.Id==id);if(!stillListed)throw new SnapshotBusy(operation+": thread "+id+" exited during inspection (Windows error "+error+").");throw new Win32Exception(error,operation+" "+id+" failed (Windows error "+error+"): "+new Win32Exception(error).Message+". Thread remains listed; no patch change was started.");}
  readonly List<IntPtr> threads=new List<IntPtr>();
  public Frozen(Process p,IntPtr code,int size,IntPtr module,int Hook,int Cave,int RelaxedRva){try{p.Refresh();var first=p.Threads.Cast<ProcessThread>().Select(t=>t.Id).OrderBy(x=>x).ToArray();foreach(int id in first){var h=OpenThread(0x0a,false,id);if(h==IntPtr.Zero){int err=Marshal.GetLastWin32Error();ThreadFailure(p,id,err,"Open thread for suspend/context");}if(SuspendThread(h)==uint.MaxValue){int err=Marshal.GetLastWin32Error();CloseHandle(h);ThreadFailure(p,id,err,"Suspend thread");}threads.Add(h);var context=Marshal.AllocHGlobal(1248+16);try{var aligned=new IntPtr((context.ToInt64()+15)&~15L);for(int i=0;i<1232;i++)Marshal.WriteByte(aligned,i,0);Marshal.WriteInt32(aligned,48,0x100001);if(!GetThreadContext(h,aligned)){int err=Marshal.GetLastWin32Error();ThreadFailure(p,id,err,"Read thread instruction pointer");}long rip=Marshal.ReadInt64(aligned,248);if((code!=IntPtr.Zero&&rip>=code.ToInt64()&&rip<code.ToInt64()+size)||(rip>=module.ToInt64()+Cave&&rip<module.ToInt64()+Cave+14)||(rip>=module.ToInt64()+Hook&&rip<module.ToInt64()+Hook+8)||(rip>=module.ToInt64()+RelaxedRva&&rip<module.ToInt64()+RelaxedRva+8))throw new SnapshotBusy("A thread is executing the hook/cave/stub.");}finally{Marshal.FreeHGlobal(context);}}
   p.Refresh();if(!first.SequenceEqual(p.Threads.Cast<ProcessThread>().Select(t=>t.Id).OrderBy(x=>x)))throw new SnapshotBusy("The game thread list changed during inspection.");
  }catch{Dispose();throw;}}
  public void Dispose(){foreach(var h in threads){ResumeThread(h);CloseHandle(h);}threads.Clear();}
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(int access,bool inherit,int id);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h,IntPtr p,byte[] b,int n,out IntPtr done);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h,IntPtr p,byte[] b,int n,out IntPtr done);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualProtectEx(IntPtr h,IntPtr p,UIntPtr size,uint protection,out uint old);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr p,UIntPtr size,uint type,uint protection);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualFreeEx(IntPtr h,IntPtr p,UIntPtr size,uint type);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushInstructionCache(IntPtr h,IntPtr p,UIntPtr size);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(int access,bool inherit,int id);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetThreadContext(IntPtr h,IntPtr context);
}
sealed class Assembler {
 readonly List<byte> b=new List<byte>();readonly Dictionary<string,int> labels=new Dictionary<string,int>();readonly List<Tuple<int,string>> fix=new List<Tuple<int,string>>();
 public void Bytes(params byte[] x){b.AddRange(x);}public void Int(int x){Bytes(BitConverter.GetBytes(x));}public void Long(long x){Bytes(BitConverter.GetBytes(x));}public void Label(string name){labels.Add(name,b.Count);}
 public void Jump(byte condition,string target){Bytes(0x0f,condition);fix.Add(Tuple.Create(b.Count,target));Int(0);}public void Jump(string target){Bytes(0xe9);fix.Add(Tuple.Create(b.Count,target));Int(0);}
 public byte[] Finish(){var result=b.ToArray();foreach(var f in fix)Array.Copy(BitConverter.GetBytes(labels[f.Item2]-f.Item1-4),0,result,f.Item1,4);return result;}
}








