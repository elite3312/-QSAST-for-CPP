import cpp

/**
 * Simple query to detect infinite loops caused by a while(true)
 * ------------------------------------------------------------------
 * Finds `while(1)` loops and checks if they contain an `if` statement
 * in their body in C/C++ code.
 */
from WhileStmt whileStmt, IfStmt ifStmt
where 
  // Match `while(1)` loops
  exists(Expr cond |
    cond.getValue() = "1" and
    cond = whileStmt.getCondition()
  ) and
  // Check if the `if` statement is contained in the `while` loop
  whileStmt.getASuccessor*() = ifStmt
select whileStmt, "This `while(1)` loop contains an `if` statement."
