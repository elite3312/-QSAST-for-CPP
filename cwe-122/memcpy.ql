/**
 * @kind path-problem
 */

 import semmle.code.cpp.dataflow.new.DataFlow
 import Flow::PathGraph
 
 module Config implements DataFlow::ConfigSig {
 
   predicate isSource(DataFlow::Node source) { 
     source.asExpr() instanceof AllocationExpr 
   }
 
   predicate isSink(DataFlow::Node sink) {
     exists(FunctionCall call |
       call.getTarget().hasName("memcpy") and
       sink.asExpr() = call.getArgument(0) and
       not exists(Expr sizeExpr |
         sizeExpr = call.getArgument(1) and
         sizeExpr instanceof SizeofOperator
       )
     )
   }
 }
 
 module Flow = DataFlow::Global<Config>;
 
 from Flow::PathNode source, Flow::PathNode sink
 where Flow::flowPath(source, sink)
 select sink.getNode(), source, sink, "Flow from malloc to sink!"
 