/**
 * @name SQL Injection Detection
 * @description Detects SQL injection vulnerabilities (CWE-89)
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id saner2025/sql-injection
 * @tags security
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery

/**
 * @name Command Injection Detection
 * @description Detects OS command injection vulnerabilities (CWE-78)
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id saner2025/command-injection
 * @tags security
 */

from CommandInjection ci
where ci.isVulnerable()
select ci, "Command injection vulnerability via $@", ci.getSource()

/**
 * @name Cross-Site Scripting Detection
 * @description Detects XSS vulnerabilities (CWE-79)
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id saner2025/xss
 * @tags security
 */

import javascript

class XSSVulnerability extends DataFlow::Configuration {
  XSSVulnerability() { this = "XSSVulnerability" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DOM::DocumentWrite write | sink = write.getArgument(0))
    or
    exists(DOM::InnerHTMLWrite write | sink = write.getRhs())
    or
    exists(DOM::LocationSink loc | sink = loc.getAReference())
  }
}

from XSSVulnerability xss, DataFlow::PathNode source, DataFlow::PathNode sink
where xss.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XSS vulnerability from $@.", source.getNode(), "user input"

/**
 * Python SQL Injection - String Formatting
 */
class PythonSQLInjectionStringFormat extends DatabaseQuery {
  PythonSQLInjectionStringFormat() {
    exists(StrConst query, BinaryExpr concat |
      concat.getOp() instanceof Add and
      concat.getAnOperand() = query and
      this.getQuery() = concat
    )
    or
    exists(FormattedValue fv |
      this.getQuery().(FString).getAValue() = fv
    )
  }
}

/**
 * Python Command Injection - os.system
 */
class PythonCommandInjectionOSSystem extends SystemCommandExecution {
  PythonCommandInjectionOSSystem() {
    exists(CallNode call |
      call.getFunction().(AttrNode).getName() = "system" and
      call.getFunction().(AttrNode).getObject().pointsTo(Module::named("os")) and
      this.getCommand() = call.getArg(0)
    )
  }
}

/**
 * Python Command Injection - subprocess with shell=True
 */
class PythonCommandInjectionSubprocess extends SystemCommandExecution {
  PythonCommandInjectionSubprocess() {
    exists(CallNode call, ControlFlowNode shell |
      call.getFunction().(AttrNode).getObject().pointsTo(Module::named("subprocess")) and
      call.getFunction().(AttrNode).getName() in ["call", "run", "Popen", "check_output"] and
      call.getArgByName("shell") = shell and
      shell.pointsTo(Value::true_()) and
      this.getCommand() = call.getArg(0)
    )
  }
}

/**
 * JavaScript XSS - innerHTML assignment
 */
class JavaScriptXSSInnerHTML extends DataFlow::Node {
  JavaScriptXSSInnerHTML() {
    exists(Assignment assign |
      assign.getLhs().(PropAccess).getPropertyName() = "innerHTML" and
      this.asExpr() = assign.getRhs()
    )
  }
}

/**
 * JavaScript Command Injection - exec
 */
class JavaScriptCommandInjectionExec extends SystemCommandExecution {
  JavaScriptCommandInjectionExec() {
    exists(CallExpr call |
      call.getCallee().(PropAccess).getPropertyName() = "exec" and
      this.getCommand() = call.getArgument(0)
    )
  }
}

/**
 * React XSS - dangerouslySetInnerHTML
 */
class ReactXSSDangerouslySetInnerHTML extends DataFlow::Node {
  ReactXSSDangerouslySetInnerHTML() {
    exists(JSXAttribute attr |
      attr.getName() = "dangerouslySetInnerHTML" and
      this.asExpr() = attr.getValue()
    )
  }
}

/**
 * Secure Pattern: Parameterized SQL Query
 */
class SecureParameterizedQuery extends DatabaseQuery {
  SecureParameterizedQuery() {
    exists(CallNode call |
      call.getFunction().(AttrNode).getName() = "execute" and
      call.getArg(0) instanceof StrConst and
      not exists(BinaryExpr concat | call.getArg(0) = concat) and
      not exists(FString fstr | call.getArg(0) = fstr) and
      call.getNumArg() > 1
    )
  }
}

/**
 * Secure Pattern: subprocess with list arguments
 */
class SecureSubprocessList extends SystemCommandExecution {
  SecureSubprocessList() {
    exists(CallNode call |
      call.getFunction().(AttrNode).getObject().pointsTo(Module::named("subprocess")) and
      call.getArg(0) instanceof List
    )
  }
}

/**
 * Secure Pattern: HTML Escaping
 */
class SecureHTMLEscape extends DataFlow::Node {
  SecureHTMLEscape() {
    exists(CallNode call |
      call.getFunction().(AttrNode).getName() = "escape" and
      (
        call.getFunction().(AttrNode).getObject().pointsTo(Module::named("html"))
        or
        call.getFunction().(AttrNode).getObject().pointsTo(Module::named("markupsafe"))
      )
    )
  }
}
