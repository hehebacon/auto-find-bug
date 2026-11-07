import importlib.util
import tempfile
import unittest
from pathlib import Path

from auto_find_bug.java_flow_analysis import analyze_java_flows


@unittest.skipUnless(importlib.util.find_spec("javalang"), "javalang optional Java parser is not installed")
class JavaFlowAnalysisTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Demo.java"
            path.write_text(source, encoding="utf-8")
            return analyze_java_flows(path)["findings"]

    def rules(self, source):
        return [item["rule_id"] for item in self.analyze(source)]

    def test_request_to_dynamic_sql(self):
        findings = self.analyze("""
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Demo {
  void run(HttpServletRequest request, Statement stmt) throws Exception {
    String input = request.getParameter("q");
    String query = "SELECT * FROM users WHERE name='" + input + "'";
    stmt.executeQuery(query);
  }
}
""")
        finding = next(item for item in findings if item["rule_id"] == "FLOW-JAVA-001")
        self.assertEqual(finding["flow"]["source"], "request.getParameter")
        self.assertEqual(finding["flow"]["sink"], "stmt.executeQuery")
        self.assertTrue(finding["flow"]["trace"])

    def test_constant_false_branch_does_not_reach_sink(self):
        self.assertNotIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String command = "safe";
    if (2 + 2 == 5) { command = request.getParameter("cmd"); }
    Runtime.getRuntime().exec(command);
  }
}
"""))

    def test_unknown_branch_is_joined_conservatively(self):
        self.assertIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request, boolean flag) throws Exception {
    String command = "safe";
    if (flag) { command = request.getParameter("cmd"); }
    Runtime.getRuntime().exec(command);
  }
}
"""))

    def test_safe_assignment_overwrites_previous_taint(self):
        self.assertNotIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String command = request.getParameter("cmd");
    command = "fixed";
    Runtime.getRuntime().exec(command);
  }
}
"""))

    def test_list_remove_and_index_retrieval_use_actual_state(self):
        self.assertNotIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.util.*;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    List<String> values = new ArrayList<>();
    values.add(request.getParameter("cmd"));
    values.add("fixed");
    values.remove(0);
    Runtime.getRuntime().exec(values.get(0));
  }
}
"""))

    def test_map_overwrite_and_get_use_actual_value(self):
        self.assertNotIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.util.*;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    Map<String,String> values = new HashMap<>();
    values.put("cmd", request.getParameter("cmd"));
    values.put("cmd", "fixed");
    Runtime.getRuntime().exec(values.get("cmd"));
  }
}
"""))

    def test_map_get_preserves_taint_when_not_overwritten(self):
        self.assertIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.util.*;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    Map<String,String> values = new HashMap<>();
    values.put("cmd", request.getParameter("cmd"));
    Runtime.getRuntime().exec(values.get("cmd"));
  }
}
"""))

    def test_array_index_and_overwrite(self):
        self.assertNotIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String[] values = new String[] { request.getParameter("cmd"), "fixed" };
    values[0] = "safe";
    Runtime.getRuntime().exec(values[0]);
  }
}
"""))

    def test_helper_argument_propagates_to_sink(self):
        self.assertIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void runCommand(String value) throws Exception {
    Runtime.getRuntime().exec(value);
  }
  void run(HttpServletRequest request) throws Exception {
    runCommand(request.getParameter("cmd"));
  }
}
"""))

    def test_helper_return_preserves_taint(self):
        self.assertIn("FLOW-JAVA-001", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Demo {
  String passthrough(String value) { return value; }
  void run(HttpServletRequest request, Statement stmt) throws Exception {
    String query = passthrough(request.getParameter("q"));
    stmt.executeQuery(query);
  }
}
"""))

    def test_process_builder_constructor_and_start_are_traced(self):
        self.assertIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) throws Exception {
    String command = request.getParameter("cmd");
    new ProcessBuilder(command).start();
  }
}
"""))

    def test_helper_return_of_safe_constant_does_not_keep_taint(self):
        self.assertNotIn("FLOW-JAVA-002", self.rules("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  String fixed(String ignored) { return "safe"; }
  void run(HttpServletRequest request) throws Exception {
    String command = fixed(request.getParameter("cmd"));
    Runtime.getRuntime().exec(command);
  }
}
"""))

    def test_statement_add_batch_reaches_execute_batch(self):
        self.assertIn("FLOW-JAVA-001", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Demo {
  void run(HttpServletRequest request, Statement statement) throws Exception {
    String sql = "SELECT '" + request.getParameter("q") + "'";
    statement.addBatch(sql);
    statement.executeBatch();
  }
}
"""))

    def test_constant_char_at_switch_prunes_unreachable_tainted_case(self):
        self.assertNotIn("FLOW-JAVA-001", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Demo {
  void run(HttpServletRequest request, Statement statement) throws Exception {
    String query = "safe";
    char mode = "A".charAt(0);
    switch (mode) {
      case 'A': query = "SELECT 1"; break;
      default: query = request.getParameter("q"); break;
    }
    statement.executeQuery(query);
  }
}
"""))

    def test_source_without_sink_is_not_reported(self):
        self.assertEqual(self.analyze("""
import javax.servlet.http.HttpServletRequest;
class Demo {
  void run(HttpServletRequest request) {
    System.out.println(request.getParameter("q"));
  }
}
"""), [])

    def test_helper_on_new_object_resolves_safe_constant_branch(self):
        self.assertNotIn("FLOW-JAVA-001", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Helper {
  String choose(String value) {
    if ((7 * 18) + 106 > 200) return "safe";
    return value;
  }
}
class Demo {
  void run(HttpServletRequest request, Statement stmt) throws Exception {
    String query = "SELECT '" + new Helper().choose(request.getParameter("q")) + "'";
    stmt.executeQuery(query);
  }
}
"""))

    def test_helper_on_new_object_preserves_tainted_return(self):
        self.assertIn("FLOW-JAVA-001", self.rules("""
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Helper {
  String pass(String value) { return value; }
}
class Demo {
  void run(HttpServletRequest request, Statement stmt) throws Exception {
    String query = "SELECT '" + new Helper().pass(request.getParameter("q")) + "'";
    stmt.executeQuery(query);
  }
}
"""))


if __name__ == "__main__":
    unittest.main()
