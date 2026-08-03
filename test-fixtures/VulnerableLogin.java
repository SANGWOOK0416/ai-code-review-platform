package com.example.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * README_DEPLOY.md의 웹훅 테스트 시나리오용 더미 파일입니다.
 * 의도적으로 SQL Injection(CWE-89) 취약점을 포함하고 있습니다 — 실제 서비스에 사용하지 마세요.
 */
public class VulnerableLogin extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/testdb", "root", "");
        Statement statement = conn.createStatement();

        // SQL Injection: 사용자 입력을 검증/이스케이프 없이 그대로 쿼리 문자열에 이어붙임
        // (PreparedStatement + 파라미터 바인딩을 썼어야 함)
        String query = "SELECT * FROM users WHERE username = '" + username
                + "' AND password = '" + password + "'";

        ResultSet rs = statement.executeQuery(query);
        if (rs.next()) {
            response.getWriter().write("로그인 성공: " + rs.getString("username"));
        } else {
            response.getWriter().write("로그인 실패");
        }
    }
}
