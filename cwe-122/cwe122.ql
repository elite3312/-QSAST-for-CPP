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

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof AllocationExpr 
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().hasName("strcpy") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    // No sanitizers for this simple example
    none()
  }
}

from HeapBufferOverflow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
//select sink.getNode(), source, sink, "Potential heap-based buffer overflow detected."

select sink, "Potential heap-based buffer overflow detected."
