/**
 * @name CWE-252: Unchecked Return Value
 * @description Functions that return error codes or critical values must have their return values checked
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/unchecked-return-value-unified
 * @tags security
 *       external/cwe/cwe-252
 */

 import cpp
 import semmle.code.cpp.controlflow.Guards
 import semmle.code.cpp.valuenumbering.GlobalValueNumbering
 
 /**
  * A function whose return value should be checked.
  */
 class CriticalFunction extends Function {
   CriticalFunction() {
     exists(string name | name = this.getName() |
       // File operations
       name = [
         "fopen", "fclose", "fputc", "fputs", "fgets", "fread", "fwrite",
         "fprintf", "fscanf", "remove", "rename", "_wrename", "RENAME",
         "fseek", "ftell"
       ] or
       // Memory operations
       name = ["malloc", "realloc", "calloc", "free"] or
       // String operations
       name = [
         "strcpy", "strncpy", "strcat", "strncat", "sprintf", "sscanf",
         "gets", "fgets", "memcpy", "memmove", "strdup", "strndup"
       ] or
       // System and process operations
       name = [
         "system", "popen", "pclose", "execl", "execlp", "execle", "execv",
         "execvp", "execvpe", "fork", "pipe", "waitpid"
       ] or
       // File system operations
       name = [
         "mkdir", "rmdir", "chmod", "chown", "stat", "mkfifo", "open",
         "creat", "unlink", "chdir"
       ] or
       // Network operations
       name = ["socket", "bind", "listen", "accept", "connect", "send", "recv"] or
       // POSIX-specific functions
       name = [
         "pthread_create", "pthread_join", "pthread_mutex_lock",
         "pthread_mutex_unlock", "sem_wait", "sem_post"
       ] or
       // Windows-specific functions
       name = [
         "CreateFile", "CreateProcess", "CreateThread", "RegCreateKey",
         "RegOpenKey"
       ] or
       // Functions returning status codes
       (
         this.getType() instanceof IntegralType and
         exists(FunctionCall fc |
           fc.getTarget() = this and
           fc.getType() instanceof IntegralType
         )
       )
     )
   }
 }
 
 /**
  * Holds if the expression is used in a condition or comparison.
  */
 predicate isCheckedInCondition(Expr e) {
   exists(IfStmt ifStmt |
     e = ifStmt.getCondition().getAChild*() or
     exists(ComparisonOperation comp |
       comp = ifStmt.getCondition() and
       comp.getAnOperand().getAChild*() = e
     )
   ) or
   exists(WhileStmt whileStmt |
     e = whileStmt.getCondition().getAChild*()
   ) or
   exists(LogicalAndExpr landExpr |
     e = landExpr.getAnOperand().getAChild*()
   ) or
   exists(LogicalOrExpr lorExpr |
     e = lorExpr.getAnOperand().getAChild*()
   ) or
   exists(ConditionalExpr condExpr |
     e = condExpr.getCondition().getAChild*()
   )
 }
 
 /**
  * Holds if the expression is used in error handling.
  */
 predicate isErrorHandled(Expr e) {
   exists(FunctionCall fc |
     fc.getTarget().getName() in [
       "error", "err", "fprintf", "printf", "perror", "exit", "abort",
       "assert", "handle_error", "ErrorHandler"
     ] and
     fc.getAnArgument().getAChild*() = e
   )
 }
 
 /**
  * Holds if the expression's value is used.
  */
 predicate isValueUsed(Expr e) {
   exists(AssignExpr assign | assign.getRValue() = e) or
   exists(ReturnStmt ret | ret.getExpr() = e) or
   exists(FunctionCall fc | fc.getAnArgument() = e) or
   exists(Variable v | v.getInitializer().getExpr() = e) or
   exists(ArrayExpr ae | ae.getArrayOffset() = e) or
   exists(PointerArithmeticOperation pao | pao.getAnOperand() = e)
 }
 
 /**
  * Holds if the expression is properly checked or used.
  */
 predicate isProperlyHandled(Expr e) {
   isCheckedInCondition(e) or
   isErrorHandled(e) or
   isValueUsed(e)
 }
 
 from FunctionCall call, CriticalFunction f
 where
   f = call.getTarget() and
   exists(ExprStmt stmt | stmt.getExpr() = call) and
   not isProperlyHandled(call) and
   not f.getType() instanceof VoidType and
   not exists(CommaExpr comma | comma.getAChild*() = call) and
   not exists(BinaryOperation bo | bo.getAnOperand().getAChild*() = call)
 select call,
   "Return value of critical function '" + f.getName() +
   "' is not checked. This could lead to unhandled error conditions. (CWE-252)"