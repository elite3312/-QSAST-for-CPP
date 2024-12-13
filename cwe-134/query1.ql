import cpp
import semmle.code.cpp.security.Security
import semmle.code.cpp.security.FunctionWithWrappers
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import Flow::PathGraph

predicate isSource(FlowSource source, string sourceType) {
  sourceType = source.getSourceType()
}

predicate isGlobalSource(FlowSource source) {
  exists(GlobalVariable v | source.asExpr() = v.getAnAccess())
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { isSource(node, _) or isGlobalSource(node) }

  predicate isSink(DataFlow::Node node) {
    exists(PrintfLikeFunction printf |
      printf.outermostWrapperFunctionCall([node.asExpr(), node.asIndirectExpr()], _)
    )
  }

  private predicate isArithmeticNonCharType(ArithmeticType type) {
    not type instanceof CharType and
    not type instanceof Char8Type and
    not type instanceof Char16Type and
    not type instanceof Char32Type
  }

  predicate isBarrier(DataFlow::Node node) {
    isSink(node) and isArithmeticNonCharType(node.asExpr().getUnspecifiedType())
    or
    isArithmeticNonCharType(node.asInstruction().(StoreInstruction).getResultType())
  }
}

module Flow = TaintTracking::Global<Config>;

from
  PrintfLikeFunction printf, string printfFunction, string sourceType, DataFlow::Node source,
  DataFlow::Node sink, Flow::PathNode sourceNode, Flow::PathNode sinkNode
where
  source = sourceNode.getNode() and
  sink = sinkNode.getNode() and
  isSource(source, sourceType) and
  printf.outermostWrapperFunctionCall([sink.asExpr(), sink.asIndirectExpr()], printfFunction) and
  Flow::flowPath(sourceNode, sinkNode)
select sink, sourceNode, sinkNode,
  "The value of this argument may come from $@ and is being used as a formatting argument to " +
    printfFunction + ".", source, sourceType
