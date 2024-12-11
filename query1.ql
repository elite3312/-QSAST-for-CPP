/**
 * @name CWE-252: Unchecked Return Value
 * @description Functions that return error codes or critical values must have their return values checked.
 * @kind problem
 * @id cpp/unchecked-return-value-enhanced
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-252
 */

 import cpp
 import semmle.code.cpp.controlflow.Guards
 import semmle.code.cpp.valuenumbering.GlobalValueNumbering
 
 /**
  * CriticalFunction identifies functions whose return values should be checked.
  * It includes a comprehensive list of critical functions across various categories.
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
         "creat", "unlink"
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
       // Functions returning status codes or critical values
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
  * Predicate to determine if the return value of a function call is properly handled.
  * A return value is considered properly handled if it is:
  * - Checked within conditional statements
  * - Used in error handling functions
  * - Assigned to variables, returned, or passed as arguments
  */
 predicate isProperlyHandled(Expr e) {
   // Check if the expression is used in a condition (e.g., if, while)
   exists(IfStmt ifStmt |
     e = ifStmt.getCondition().getAChild*() or
     exists(ComparisonOperation comp |
       comp = ifStmt.getCondition() and
       comp.getAnOperand().getAChild*() = e
     )
   ) or
   exists(WhileStmt whileStmt |
     e = whileStmt.getCondition().getAChild*() or
     e = whileStmt.getCondition()
   ) or
   exists(LogicalAndExpr landExpr |
     e = landExpr.getAnOperand().getAChild*()
   ) or
   exists(LogicalOrExpr lorExpr |
     e = lorExpr.getAnOperand().getAChild*()
   ) or
   exists(ConditionalExpr condExpr |
     e = condExpr.getCondition().getAChild*()
   ) or
   // Check if the expression is used in error handling functions
   exists(FunctionCall fc |
     fc.getTarget().getName() in [
       "error", "err", "fprintf", "printf", "perror", "exit", "abort",
       "assert", "handle_error", "ErrorHandler"
     ] and
     fc.getAnArgument().getAChild*() = e
   ) or
   // Check if the expression is assigned, returned, or passed as an argument
   exists(AssignExpr assign | assign.getRValue() = e) or
   exists(ReturnStmt ret | ret.getExpr() = e) or
   exists(FunctionCall fc | fc.getAnArgument() = e) or
   exists(Variable v | v.getInitializer().getExpr() = e) or
   exists(ArrayExpr ae | ae.getArrayOffset() = e) or
   exists(PointerArithmeticOperation pao | pao.getAnOperand() = e)
 }
 
 /**
  * Predicate to determine if the function call's return value is not properly handled.
  */
 predicate isReturnValueUnchecked(FunctionCall call) {
   // The return value is used in an expression statement (direct call)
   exists(ExprStmt stmt | stmt.getExpr() = call) and
   // The return value is not properly handled
   not isProperlyHandled(call) and
   // Exclude void functions
   not call.getTarget().getType() instanceof VoidType and
   // Exclude cases where the function is called in a comma expression
   not exists(CommaExpr comma | comma.getAChild*() = call) and
   // Exclude cases where the function is part of a binary operation
   not exists(BinaryOperation bo | bo.getAnOperand().getAChild*() = call)
 }
 
 /**
  * Main query to find unchecked return values of critical functions.
  */
 from FunctionCall call, CriticalFunction f
 where
   f = call.getTarget() and
   not call.isInMacroExpansion() and
   isReturnValueUnchecked(call)
 select call,
   "Return value of critical function '" + f.getName() +
   "' is not checked. This could lead to unhandled error conditions. (CWE-252)"