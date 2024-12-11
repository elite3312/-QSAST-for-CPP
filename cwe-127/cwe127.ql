/**
 * @id cpp/buffer-underread
 * @kind path-problem
 * @name 'Buffer overread'
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph

predicate isPointerOrArray(Expr expr) {
  expr.getType().getUnspecifiedType() instanceof PointerType or
  expr.getType().getUnspecifiedType() instanceof ArrayType
}

predicate pointerAccessAsParam(DataFlow::Node sink) {
  isPointerOrArray(sink.asExpr()) and
  exists(FunctionCall fc |
    (
      fc.getTarget().hasName("strcpy") or 
      fc.getTarget().hasName("strncpy") or 
      fc.getTarget().hasName("memcpy") or
      fc.getTarget().hasName("memmove") or
      fc.getTarget().hasName("wcscpy") or 
      fc.getTarget().hasName("wcsncpy")
    ) and
    sink.asExpr() = fc.getArgument(1)
  )
}

predicate pointerAccessAsArray(DataFlow::Node sink) {
  isPointerOrArray(sink.asExpr()) and
  exists(ArrayExpr ae |
    ae.getArrayBase() = sink.asExpr()
  )
}

module PointerSubOperation implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof PointerSubExpr and
    isPointerOrArray(source.asExpr().(PointerSubExpr).getLeftOperand())
  }

  predicate isSink(DataFlow::Node sink) {
    pointerAccessAsParam(sink) or
    pointerAccessAsArray(sink)
  }
}

module Flow = DataFlow::Global<PointerSubOperation>;


from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select source.getNode(), source, sink, "Pointer is accessed after being decremented"

