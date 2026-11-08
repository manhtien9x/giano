// @category GiaNo
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class ExportGiaNo extends GhidraScript {
 public void run() throws Exception {
  File dir=new File(getScriptArgs()[0]);dir.mkdirs();
  DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
  int ok=0,failed=0;
  try(PrintWriter out=new PrintWriter(new File(dir,"decompiled.c"));PrintWriter idx=new PrintWriter(new File(dir,"functions.tsv"))) {
   FunctionIterator fs=currentProgram.getFunctionManager().getFunctions(true);
   while(fs.hasNext() && !monitor.isCancelled()){
    Function f=fs.next();if(f.isExternal()||f.isThunk())continue;
    idx.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+f.getBody().getNumAddresses());
    DecompileResults r=dec.decompileFunction(f,20,monitor);
    if(r.decompileCompleted()&&r.getDecompiledFunction()!=null){out.println("\n/* "+f.getEntryPoint()+" "+f.getName()+" */");out.println(r.getDecompiledFunction().getC());ok++;}
    else {out.println("/* FAILED "+f.getEntryPoint()+" "+r.getErrorMessage()+" */");failed++;}
   }
  } finally {dec.dispose();}
  println("Exported "+ok+" functions; failed "+failed);
 }
}
