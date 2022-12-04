package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req=(HttpServletRequest)request;
        HttpServletResponse res=(HttpServletResponse)response;
        req.setCharacterEncoding("UTF-8");

        //토큰 : cos   --- 이걸 만들어 줘야 함
        //id ,pw 가 정상적으로 들어와서 로그인이 완료 되면 토큰을 만드렁주고 그걸 응답을 해준다.
        //-- 이후 요청할 대 마다 header에 Authorization에 valur값으로 토큰을 가지고 옴
        //그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지마 검증만 하면 됨 (RSA,HS256)
        if(req.getMethod().equals("POST")){
            System.out.println("POST요청됨!");
            String headerAuth=req.getHeader("Authorization");
            //POSTMAN에서  Headers에 Authorization 넣어야 함 !
            System.out.println(headerAuth);
            System.out.println("필터3");

            //postman   http://localhost:8585/home
            //Headers에   KEY : Authorization  VALUES : hello 요청
            //hello 라고응답

            //Authorization에 cos라고 넣어야  동작 함
            if(headerAuth.equals("cos")){
                chain.doFilter(req,res);
            }else{
                PrintWriter outPrintWriter=res.getWriter();
                outPrintWriter.println("인증안됨!");
            }


        }
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
