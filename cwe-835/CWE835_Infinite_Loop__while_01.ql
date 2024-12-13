import cpp

/**
 * Detect infinite loops caused by while statements
 */
predicate ensureWhileloopType(Loop loop, WhileStmt whileStatement) {
  loop.toString() = whileStatement.toString()
}

predicate checkStatements(Loop loop, Expr condition, boolean pool) {
  condition = loop.getCondition() 
  and 
  pool = true
  or
  exists(IfStmt ifstatement, Stmt exitStatement | 
    ifstatement.getEnclosingStmt() = loop.getStmt() and
    ifstatement.getCondition() = condition and
    (
      exitStatement.(BreakStmt).getTarget() = loop or
      exitStatement.(ReturnStmt).getEnclosingStmt*() = loop.getStmt()
    ) and
    (
      pool = false and exitStatement.getEnclosingStmt() = ifstatement.getThen()
      or
      pool = true and exitStatement.getEnclosingStmt() = ifstatement.getElse()
    )
  )
}

predicate checkLogicalExpressions(Expr condition, Expr nextCondition, boolean logCond) {
  condition = nextCondition and logCond = false
  or
  checkLogicalExpressions(condition.(LogicalAndExpr).getAnOperand(), nextCondition, logCond)
  or
  checkLogicalExpressions(condition.(LogicalOrExpr).getAnOperand(), nextCondition, logCond)
}

from 
  WhileStmt whileStatement, Loop loop, BinaryOperation test, Expr nextCondition, boolean pool, boolean logCond, IfStmt ifStmt
where
  ensureWhileloopType(loop, whileStatement) and
  checkStatements(loop, nextCondition, pool) and
  checkLogicalExpressions(nextCondition, test, logCond) and
  whileStatement.getASuccessor*() = ifStmt
select loop, 
  "Potential infinite loop caused by while statement without break. "
