import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow
/**
 * @name Heap-based buffer overflow
 * @description Detects heap-based buffer overflow vulnerabilities.
 * @kind problem
 * @problem.severity error
 * @id cpp/heap-buffer-overflow
 */

class HeapBufferOverflow extends TaintTracking::Configuration {
  HeapBufferOverflow() { this = "HeapBufferOverflow" }

  //considers any expression that represents a memory allocation 
  //(like malloc or new) as a source.
  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof AllocationExpr 
  }

  //looks for calls to strcpy, a function known for its vulnerability 
  //to buffer overflows if the destination buffer is not properly sized.
  // The sink is identified as the first argument of the strcpy call.
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().hasName("strcpy")  and
      sink.asExpr() = call.getArgument(0)
    )
  }

  //Sanitizers are typically functions that validate or check data 
  //before it is used, which could prevent vulnerabilities.
  //here we define none
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    // No sanitizers for this simple example
    none()
  }
}

from HeapBufferOverflow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
//select sink.getNode(), source, sink, "Potential heap-based buffer overflow detected."

select source,"new or malloc",sink, "use of strcpy"
