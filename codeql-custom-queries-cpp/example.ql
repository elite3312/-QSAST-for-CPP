/**
 * @name single statement block
 * @kind problem
 * @problem.severity warning
 * @id cpp/example/single-statement-block
 */

import cpp
 
from BlockStmt b
where b.getNumStmt() = 1
select b, "This is a block with a single statement"
