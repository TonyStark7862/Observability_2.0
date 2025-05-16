import re
import json
from typing import Any, Dict, List, Optional, Tuple, Union
from sql_metadata import Parser
import pandas as pd

def generate_table_mapping_from_create_statements(create_statements: str) -> Dict[str, List[str]]:
    result_mapping = {}
    statements = create_statements.split(';')
    
    for statement in statements:
        statement = statement.strip()
        if not statement:
            continue
            
        create_match = re.match(r'\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"\[\w\.]+)(?:\s+AS\b)?', 
                                statement, re.IGNORECASE)
        
        if not create_match:
            continue
            
        table_name = create_match.group(1)
        if '.' in table_name:
            table_name = table_name.split('.')[-1]
        table_name = re.sub(r'[`"\[\]]', '', table_name).lower()
        
        columns = ['*']
        
        view_select_match = re.search(r'\bAS\b\s*\(\s*SELECT\s+(.*?)(?:\bFROM\b|\);?|$)', 
                                    statement, re.IGNORECASE | re.DOTALL)
        
        if view_select_match:
            select_columns = view_select_match.group(1).strip()
            col_list = re.split(r',\s*', select_columns)
            for col in col_list:
                col = col.strip()
                alias_match = re.search(r'\bAS\b\s+([`"\[\w]+)', col, re.IGNORECASE)
                if alias_match:
                    col_name = alias_match.group(1)
                else:
                    parts = re.split(r'\.', col)
                    col_name = parts[-1].strip() if parts else col.strip()
                    col_name = re.sub(r'.*\(|\).*', '', col_name).strip() 
                
                col_name = re.sub(r'[`"\[\]]', '', col_name).lower()
                if col_name and col_name not in columns and col_name != '*':
                    columns.append(col_name)
        else:
            columns_match = re.search(r'\(\s*(.*?)\s*\)[^)]*$', statement, re.DOTALL)
            if columns_match:
                columns_def = columns_match.group(1).strip()
                col_defs = []
                current_def = ""
                paren_level = 0
                
                for char in columns_def:
                    if char == '(': paren_level += 1
                    elif char == ')': paren_level -= 1
                    
                    if char == ',' and paren_level == 0:
                        col_defs.append(current_def.strip())
                        current_def = ""
                    else:
                        current_def += char
                
                if current_def.strip():
                    col_defs.append(current_def.strip())
                
                for col_def in col_defs:
                    if re.match(r'\s*(CONSTRAINT|PRIMARY\s+KEY|FOREIGN\s+KEY|UNIQUE|CHECK|INDEX)', 
                                col_def, re.IGNORECASE):
                        continue
                    
                    col_match = re.match(r'\s*([`"\[\w]+)', col_def)
                    if col_match:
                        col_name = col_match.group(1)
                        col_name = re.sub(r'[`"\[\]]', '', col_name).lower()
                        if col_name not in columns:
                            columns.append(col_name)
        
        if len(columns) > 1:
            result_mapping[table_name] = columns
    return result_mapping

class SQLQueryInspector:
    def __init__(self, query):
        self.query = query
        self.issues = []

    def inspect_query(self):
        if not (re.match(r'\s*SELECT', self.query, re.IGNORECASE | re.DOTALL) or
                re.match(r'\s*WITH\s+.*?\s+AS\s*\(.*?\)\s*SELECT', self.query, re.IGNORECASE | re.DOTALL)):
                self.issues.append("Only SELECT statements or CTEs (WITH...SELECT) are allowed.")

        disallowed_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'GRANT', 'REVOKE']
        for keyword in disallowed_keywords:
            if re.search(fr'\b{keyword}\b', self.query, re.IGNORECASE):
                self.issues.append(f"Potential disallowed operation detected: '{keyword}'.")

        unsafe_keywords = ['xp_cmdshell', 'exec(\s|\()', 'sp_', 'xp_', ';\s*--']
        for keyword_pattern in unsafe_keywords:
                if re.search(fr'{keyword_pattern}', self.query, re.IGNORECASE):
                    match = re.search(fr'{keyword_pattern}', self.query, re.IGNORECASE)
                    actual_keyword = match.group(0).strip() if match else keyword_pattern
                    self.issues.append(f"Potentially unsafe SQL pattern '{actual_keyword}' detected.")
        
        if re.search(r'\b(LIMIT|OFFSET)\b', self.query, re.IGNORECASE) and \
           not re.search(r'\bORDER\s+BY\b', self.query, re.IGNORECASE):
            self.issues.append("Use of LIMIT/OFFSET without ORDER BY may result in unpredictable results.")

        if re.search(r';(?!\s*(--.*)?$)', self.query.strip()):
            is_already_flagged_as_unsafe_semicolon_comment = False
            for issue in self.issues:
                if ';\s*--' in issue and "Potentially unsafe SQL pattern" in issue:
                    is_already_flagged_as_unsafe_semicolon_comment = True
                    break
            if not is_already_flagged_as_unsafe_semicolon_comment:
                 self.issues.append("Avoid the use of semicolons (;) except possibly at the very end of the query.")


        join_pattern = r'\bJOIN\s+([\w.]+)(\s+\w+)?(?!\s+(ON|USING)\b)'
        potential_cartesian_joins = re.findall(join_pattern, self.query, re.IGNORECASE)
        if potential_cartesian_joins:
                if not re.search(r'\bCROSS\s+JOIN\b', self.query, re.IGNORECASE):
                    join_match = re.search(join_pattern, self.query, re.IGNORECASE)
                    if join_match:
                        substring_after_join = self.query[join_match.end():]
                        next_join_match = re.search(r'\bJOIN\b', substring_after_join, re.IGNORECASE)
                        search_area = substring_after_join if not next_join_match else substring_after_join[:next_join_match.start()]
                        if not re.search(r'\b(ON|USING)\b', search_area, re.IGNORECASE | re.DOTALL):
                            self.issues.append("Use of JOIN without an ON/USING clause may result in a Cartesian product. Specify join conditions or use CROSS JOIN.")

        if re.search(r'\bUNION\b', self.query, re.IGNORECASE):
            self.issues.append("UNION queries detected. Ensure column counts and types match in each SELECT.")

        if self.issues:
            issues_str = "Detected issues while validating SQL query:\n" + "\n".join(f"- {issue}" for issue in self.issues)
            return issues_str
        else:
            return self.query

agg_pattern = re.compile(r'^(COUNT|SUM|AVG|MIN|MAX)\s*\(\s*(?:\*|\w+|\bDISTINCT\b\s+\w+)\s*\)', re.IGNORECASE)

def check_and_clean_columns(columns_raw, ctes_present, known_base_table_aliases, known_base_table_names):
    cleaned_columns_for_validation = []
    known_prefixes = known_base_table_aliases.union(known_base_table_names)
    for col_raw_item in columns_raw:
        col_raw = str(col_raw_item)
        if agg_pattern.match(col_raw):
            continue
        if ctes_present:
            if '.' in col_raw:
                parts = col_raw.split('.', 1)
                prefix = parts[0].lower()
                col_name = parts[1]
                if prefix in known_prefixes:
                    cleaned_columns_for_validation.append(col_name.lower())
        else:
            if '.' in col_raw:
                col_name = col_raw.split('.')[-1].lower()
                cleaned_columns_for_validation.append(col_name)
            elif col_raw != '*':
                col_name = col_raw.lower()
                cleaned_columns_for_validation.append(col_name)
    return list(set(cleaned_columns_for_validation))

def validate_columns(extracted_tables, cleaned_columns_for_validation, table_column_mapping):
    extracted_tables_lower = [str(t).lower() for t in extracted_tables]
    valid_columns_for_query = set(['*'])
    unknown_tables = []
    
    for table_name_lower in extracted_tables_lower:
        if table_name_lower in table_column_mapping:
            valid_columns_for_query.update(col.lower() for col in table_column_mapping[table_name_lower])
        else:
            if table_name_lower not in unknown_tables:
                unknown_tables.append(table_name_lower)
    
    if unknown_tables:
        error_message = f"Query references undefined tables: {', '.join(sorted(unknown_tables))}"
        return False, [error_message]
        
    invalid_columns = []
    for col in cleaned_columns_for_validation:
        if col not in valid_columns_for_query:
            if col != '*':
                invalid_columns.append(col)
    
    if invalid_columns:
        sorted_invalid_cols = sorted(list(set(invalid_columns)))
        sorted_tables_referenced = sorted(list(set(extracted_tables_lower)))
        error_message = f"Columns [{', '.join(sorted_invalid_cols)}] are not defined for the referenced tables [{', '.join(sorted_tables_referenced)}]"
        return False, [error_message]
    else:
        return True, []

def query_validator(query: str, current_schema_mapping: Dict[str, List[str]]) -> str:
    inspector = SQLQueryInspector(query)
    output_query_or_error = inspector.inspect_query()
    if output_query_or_error != query:
        return output_query_or_error
    else:
        try:
            parser = Parser(query)
            tables_from_parser_for_simple_check = [str(t).lower() for t in parser.tables]
            columns_raw = parser.columns
            ctes_present = bool(parser.with_names)

            if not tables_from_parser_for_simple_check and not ctes_present:
                is_simple_select_ok = True
                if columns_raw:
                    for c_item in columns_raw:
                        c = str(c_item)
                        if not (c.isdigit() or c == '*' or agg_pattern.match(c) or 
                                re.match(r'^\w+\(\s*\)$', c)):
                            is_simple_select_ok = False
                            break
                if is_simple_select_ok:
                    return query
                else:
                    return "Validation Error: Columns specified without a valid table or CTE reference."

            schema_defined_base_tables = set(current_schema_mapping.keys())

            base_table_aliases = {
                str(alias).lower(): str(table).lower()
                for alias, table in parser.tables_aliases.items()
                if str(table).lower() in schema_defined_base_tables
            }
            known_base_table_aliases_set = set(base_table_aliases.keys())
            
            columns_cleaned_for_validation = check_and_clean_columns(
                columns_raw, ctes_present, known_base_table_aliases_set, schema_defined_base_tables
            )
            
            actual_base_tables_to_validate = [
                t_parser for t_parser in tables_from_parser_for_simple_check 
                if t_parser in schema_defined_base_tables
            ]

            is_valid, validation_issues = validate_columns(
                actual_base_tables_to_validate, 
                columns_cleaned_for_validation,
                current_schema_mapping
            )
            
            if is_valid:
                return query
            else:
                return f"Validation Error: {', '.join(validation_issues)}"

        except Exception as e:
            if "Unknown token" in str(e) or "Parse" in str(e) or "Syntax error" in str(e):
                return f"Validation Error: Failed to parse the query structure. Check syntax. (Details: {e})"
            else:
                return f"Validation Error: An unexpected issue occurred during validation. (Details: {e})"

JUDGE_MODEL_ID = "example-judge-llm" 

def abc_response(model: str, prompt: str, temperature: float = 0.7, max_tokens: int = 250) -> Tuple[str, float, int, int]:
    print(f"--- CUSTOM FRAMEWORK: abc_response CALLED (MOCK) ---")
    if "judge" in model.lower(): 
        if "TASK INTRODUCTION:" in prompt and "EVALUATION CRITERIA:" in prompt and "LLM OUTPUT TO EVALUATE:" in prompt :
            raw_score = 8 
            reason_val = ("G-Eval Mock Reasoning: Syntactic: OK. TableSel: OK. ColSel: OK. Filter: OK. Join: N/A. Group/Agg: N/A. Semantic: Good. Efficiency: OK. Overall positive.")
            return json.dumps({"score": raw_score, "reason": reason_val}), 0.8, 200, 50
        else: 
            return json.dumps({"score": 0.5, "reason": "Neutral assessment from judge."}), 0.5, 100, 15
    else: 
        return f"Generated response by {model} for prompt: {prompt[:30]}...", 1.0, 50, 50

class CustomScoreResult:
    def __init__(self, name: str, score: float, reason: Optional[str] = None, metadata: Optional[Dict] = None):
        self.name = name; self.score = score; self.reason = reason
        self.metadata = metadata if metadata is not None else {}
    def to_dict(self) -> Dict:
        return {"name": self.name, "score": self.score, "reason": self.reason, "metadata": self.metadata}

class CustomBaseMetric:
    def __init__(self, name: str): self.name = name

class CustomLLMAsJudgeMetric(CustomBaseMetric):
    def __init__(self, name: str, judge_model_id: str, prompt_template: str):
        super().__init__(name=name); self.judge_model_id = judge_model_id; self.prompt_template = prompt_template
    def _format_prompt(self, **kwargs) -> str: return self.prompt_template.format(**kwargs)
    def _parse_judge_response(self, judge_response_str: str) -> Tuple[float, str, Optional[Dict]]:
        try:
            data = json.loads(judge_response_str); score = float(data.get("score", 0.0))
            reason = str(data.get("reason", "No reason provided by judge."))
            metadata = {k: v for k, v in data.items() if k not in ["score", "reason"]}
            return score, reason, metadata if metadata else {}
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            return 0.0, f"Error parsing judge response: {e}. Response: '{judge_response_str}'", {"raw_judge_response": judge_response_str}
    def score_llm_metric(self, **kwargs) -> CustomScoreResult:
        try: prompt_for_judge = self._format_prompt(**kwargs)
        except KeyError as e: return CustomScoreResult(self.name, 0.0, f"Missing key for prompt formatting: {e}", metadata=kwargs)
        judge_response_str, _, _, _ = abc_response(self.judge_model_id, prompt_for_judge)
        final_score, reason, metadata = self._parse_judge_response(judge_response_str)
        return CustomScoreResult(self.name, final_score, reason, metadata)

class CustomGEval(CustomLLMAsJudgeMetric):
    PROMPT_TEMPLATE = """*** TASK:
Based on the following task description and evaluation criteria, evaluate the provided LLM OUTPUT.
*** TASK INTRODUCTION:
{task_introduction}
*** EVALUATION CRITERIA:
{evaluation_criteria}
*** LLM OUTPUT TO EVALUATE:
{output}
*** YOUR EVALUATION:
Provide detailed reasoning for each criterion. Assign an overall score (0-10 integer or 0.0-1.0 float).
Return JSON: {{"score": <score>, "reason": "<detailed reasoning>"}}"""
    def __init__(self, task_introduction: str, evaluation_criteria: str, judge_model_id: str):
        super().__init__(name="sql_relevancy_score", judge_model_id=judge_model_id, prompt_template=self.PROMPT_TEMPLATE)
        self._task_introduction = task_introduction; self._evaluation_criteria = evaluation_criteria
    def _format_prompt(self, output: str, **ignored_kwargs) -> str:
        return self.prompt_template.format(task_introduction=self._task_introduction, evaluation_criteria=self._evaluation_criteria, output=output)
    def score(self, output: str, **ignored_kwargs) -> CustomScoreResult:
        result = super().score_llm_metric(output=output)
        parsed_score = result.score; final_reason = result.reason; metadata = result.metadata
        if isinstance(parsed_score, (int, float)) and parsed_score > 1.0 and parsed_score <= 10.0:
            normalized_score = parsed_score / 10.0
            final_reason = f"(Score normalized from {parsed_score}/10) {result.reason}"
            metadata["original_judge_score"] = parsed_score
            return CustomScoreResult(self.name, normalized_score, final_reason, metadata)
        return result

def txt2sql_metrics(user_question: str, predicted_sql: str, db_schema: str) -> str:
    results_list = []
    print(f"\n--- Evaluating SQL for Q: '{user_question[:70]}...' ---")

    print("1. Parsing DB schema dynamically using validator's DDL parser...")
    table_definitions_from_ddl = generate_table_mapping_from_create_statements(db_schema)
    
    if not table_definitions_from_ddl and db_schema.strip():
        print("   WARNING: DB Schema DDL was provided but parsing yielded no table definitions. SQL Validator will operate as if no tables are known from the schema.")
    elif not table_definitions_from_ddl and not db_schema.strip():
        print("   INFO: DB Schema DDL string is empty. SQL Validator will operate as if no tables are known from the schema.")
    else:
        print(f"   INFO: DB Schema DDL parsed. Known tables for validator: {list(table_definitions_from_ddl.keys())}")

    print("2. Performing Comprehensive SQL Validation (Strict Dynamic Schema)...")
    validation_result_str = query_validator(predicted_sql, table_definitions_from_ddl)

    validation_score = 0.0 
    validation_reason = "Pass (Comprehensive Validation)"
    
    if validation_result_str != predicted_sql: 
        validation_score = 1.0 
        validation_reason = validation_result_str 

    comprehensive_validation_metric = CustomScoreResult(
        name="sql_safety_score", 
        score=validation_score,
        reason=validation_reason,
        metadata={"raw_validator_output": validation_result_str} 
    )
    results_list.append(comprehensive_validation_metric.to_dict())
    print(f"   Comprehensive SQL Validation Score: {validation_score}, Reason (first 100 chars): {validation_reason[:100]}...")

    print("3. Running LLM-based SQL Evaluation (GEval)...")
    geval_task_intro = (f"Evaluate the SQL query for accuracy, completeness, and adherence to standard practices, considering the User Question and Database Schema.\nUser Question: \"{user_question}\"\nDatabase Schema (CREATE TABLE statements):\n{db_schema}")
    geval_criteria = """
Please assess based on:
1.  **Syntactic Correctness**: Is the SQL syntax valid? (Assume basic programmatic checks already done; focus on complex syntax if any).
2.  **Table Selection**: Correct tables used as per schema and question?
3.  **Column Selection**: Appropriate and valid columns selected (semantic appropriateness)?
4.  **Filtering Accuracy**: WHERE clauses correct and complete?
5.  **Join Logic (if applicable)**: Joins correct?
6.  **Grouping/Aggregation (if applicable)**: Correct use of GROUP BY, aggregates?
7.  **Semantic Correctness & Completeness**: Does it fully address the user's question?
8.  **Efficiency (optional consideration)**: Any obvious inefficiencies?
Return a 0-10 score and detailed reasoning.
"""
    geval_metric = CustomGEval(task_introduction=geval_task_intro, evaluation_criteria=geval_criteria, judge_model_id=JUDGE_MODEL_ID)
    geval_result = geval_metric.score(output=predicted_sql)
    results_list.append(geval_result.to_dict())
    print(f"   G-Eval Score: {geval_result.score}, Reason (first 100 chars): {str(geval_result.reason)[:100]}...")

    column_hallucination_metric = CustomScoreResult(
        name="sql_column_hallucination_score",
        score=validation_score,
        reason=validation_reason,
        metadata={"raw_validator_output": validation_result_str}
    )
    results_list.append(column_hallucination_metric.to_dict())

    print("--- Evaluation Complete ---")
    return json.dumps(results_list, indent=2)

if __name__ == '__main__':
    print("--- Text-to-SQL Multi-Metric Evaluation Demo (Strict Dynamic Schema Validator) ---")

    ecommerce_schema = """
    CREATE TABLE customers (
        customer_id INT PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        email VARCHAR(100) UNIQUE,
        phone VARCHAR(20),
        address VARCHAR(200),
        city VARCHAR(50),
        state VARCHAR(2),
        zip_code VARCHAR(10),
        registration_date DATE
    );
    
    CREATE TABLE products (
        product_id INT PRIMARY KEY,
        product_name VARCHAR(100) NOT NULL,
        description TEXT,
        category VARCHAR(50),
        price DECIMAL(10, 2) NOT NULL,
        stock_quantity INT DEFAULT 0,
        supplier_id INT
    );
    
    CREATE TABLE orders (
        order_id INT PRIMARY KEY,
        customer_id INT NOT NULL,
        order_date TIMESTAMP NOT NULL,
        status VARCHAR(20) NOT NULL,
        total_amount DECIMAL(12, 2),
        shipping_address VARCHAR(200),
        shipping_city VARCHAR(50),
        shipping_state VARCHAR(2),
        shipping_zip VARCHAR(10),
        FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
    );
    
    CREATE TABLE order_items (
        order_id INT,
        product_id INT,
        quantity INT NOT NULL,
        unit_price DECIMAL(10, 2) NOT NULL,
        PRIMARY KEY (order_id, product_id),
        FOREIGN KEY (order_id) REFERENCES orders(order_id),
        FOREIGN KEY (product_id) REFERENCES products(product_id)
    );
    
    CREATE VIEW customer_orders AS (
        SELECT c.customer_id, c.first_name, c.last_name, 
               o.order_id, o.order_date, o.total_amount
        FROM customers c
        JOIN orders o ON c.customer_id = o.customer_id
    );
    """
    
    test_cases_data = [
        {
            "id": "ec001", 
            "use_case": "Valid Simple Select", 
            "schema_name": "ecommerce", 
            "question": "List all customer names and emails", 
            "sql": "SELECT first_name, last_name, email FROM customers;"
        },
        {
            "id": "ec002", 
            "use_case": "Valid WHERE Clause", 
            "schema_name": "ecommerce", 
            "question": "Find products that cost more than $50", 
            "sql": "SELECT product_name, price FROM products WHERE price > 50;"
        },
        {
            "id": "ec003", 
            "use_case": "Valid JOIN", 
            "schema_name": "ecommerce", 
            "question": "List all orders with customer information", 
            "sql": "SELECT o.order_id, o.order_date, c.first_name, c.last_name FROM orders o JOIN customers c ON o.customer_id = c.customer_id;"
        },
        {
            "id": "ec004", 
            "use_case": "Valid Aggregate", 
            "schema_name": "ecommerce", 
            "question": "What is the total value of all orders?", 
            "sql": "SELECT SUM(total_amount) AS total_sales FROM orders;"
        },
        {
            "id": "ec005", 
            "use_case": "Valid GROUP BY", 
            "schema_name": "ecommerce", 
            "question": "How many orders has each customer made?", 
            "sql": "SELECT customer_id, COUNT(order_id) AS order_count FROM orders GROUP BY customer_id;"
        },
        {
            "id": "ec006", 
            "use_case": "Valid Complex Query", 
            "schema_name": "ecommerce", 
            "question": "What are the top 5 most purchased products?", 
            "sql": "SELECT p.product_name, SUM(oi.quantity) AS total_quantity FROM products p JOIN order_items oi ON p.product_id = oi.product_id GROUP BY p.product_name ORDER BY total_quantity DESC LIMIT 5;"
        },
        {
            "id": "ec007", 
            "use_case": "Valid View Query", 
            "schema_name": "ecommerce", 
            "question": "Get all customer orders from the view", 
            "sql": "SELECT customer_id, first_name, last_name, order_id, order_date FROM customer_orders;"
        },
        {
            "id": "ec008", 
            "use_case": "Invalid Table", 
            "schema_name": "ecommerce", 
            "question": "Get information from non-existent table", 
            "sql": "SELECT * FROM inventory;"
        },
        {
            "id": "ec009", 
            "use_case": "Invalid Column", 
            "schema_name": "ecommerce", 
            "question": "Get customer discount rates", 
            "sql": "SELECT customer_id, discount_rate FROM customers;"
        },
        {
            "id": "ec010", 
            "use_case": "Unsafe Operation", 
            "schema_name": "ecommerce", 
            "question": "Get customer data and drop products table", 
            "sql": "SELECT * FROM customers; DROP TABLE products;"
        }
    ]

    schemas = {"ecommerce": ecommerce_schema}
    results_data = []

    for index, row in enumerate(test_cases_data):
        print(f"\nProcessing Test Case ID: {row['id']} ({row['use_case']})")
        current_schema_str = schemas.get(row['schema_name'], ecommerce_schema) 
        metrics_json_str = txt2sql_metrics(
            user_question=row['question'], 
            predicted_sql=row['sql'], 
            db_schema=current_schema_str
        )
        metrics_list = json.loads(metrics_json_str)
        
        row_results = {
            "test_id": row['id'], 
            "use_case": row['use_case'], 
            "question": row['question'], 
            "predicted_sql": row['sql'], 
            "schema_name_used": row['schema_name']
        }
        
        for metric in metrics_list:
            metric_name = metric['name'].lower()
            row_results[f"{metric_name}"] = metric.get('score')
            row_results[f"{metric_name}_reasoning"] = metric.get('reason', "No reason provided")[:100] + "..."
        
        results_data.append(row_results)
        
        print(f"  SQL: {row['sql']}")
        for metric in metrics_list:
            print(f"  {metric['name']}: {metric.get('score')} - {metric.get('reason', 'No reason')[:80]}...")
        
    print("\n--- Evaluation Summary ---")
    print(f"{'ID':<8} {'Use Case':<25} {'Valid?':<10} {'Score':<10}")
    print("-" * 55)
    for result in results_data:
        valid = "No" if result.get('sql_safety_score', 0) > 0 else "Yes"
        relevancy_score = result.get('sql_relevancy_score', 'N/A')
        print(f"{result['test_id']:<8} {result['use_case'][:25]:<25} {valid:<10} {relevancy_score:<10}")
