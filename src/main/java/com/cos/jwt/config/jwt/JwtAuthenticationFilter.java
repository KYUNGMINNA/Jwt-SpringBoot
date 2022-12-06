package com.cos.jwt.config.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 기본적으로 UsernamePasswordAuthenticationFilter 있음

//login 요청해서 Username,password 전송하면 (POST)
//UsernamePasswordAuthenticationFilter가 동작을 함

//그러나 지금 SecutyConfig  에서 formLogin .disalbe 해놔서 동작 안함
// disable 안했으면 login 요청올 때 무조건 옴
//아니면 securiyconfig에서 .addFilter(new JwtAuthenticationFilter(authenticationManager()))
//시큐리티 필터체인에 filter를 걸면 됨
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    // @RequiredArgsConstructor는 final로 선언된 변수들을 자동으로 생성자로 만들어줌

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중!");

        //1.username,password 받아서
        try {
            /* -- www.x-form 방식으로 보낼때 만 허용    : 가장 원시적인 방법으로 확인
            BufferedReader br=request.getReader();
            String input=null;
            while((input=br.readLine())!=null){
                System.out.println(input);
            }
            System.out.println(request.getInputStream().toString());
            */

            System.out.println(request.getInputStream().toString());


            //Body raw+JSON으로 보내게 된다면 밑에 처럼 작성해야함
            ObjectMapper om=new ObjectMapper(); //JSON 데이터를 파싱해줌
            User user=om.readValue(request.getInputStream(), User.class); //user에 Object가 담김
            System.out.println(user);

            //폼 로그인하면 자동으로 만들어주는데 , 지금은 form로그인을 안쓰기 때문에 직접 만들어 줘야함
            UsernamePasswordAuthenticationToken authenticationToken=
                    new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());


            //prinCipalDeatilsService의 loadUserByUsername()함수가 실행된 후
            // 정상이면 authenticartion 리턴
            Authentication authentication=authenticationManager.authenticate(authenticationToken);
            //DBㅔㅇ 있는 username과 password가 일치!
            //authentication에 내 로그인 정보가 담김 !




            //authentication 객체가 session 영역에 저장됨 ->로그인이 되었다는 뜻.
            PrincipalDetails principalDetails=(PrincipalDetails)authentication.getPrincipal();

            System.out.println("로그인 완료됨 "+principalDetails.getUser().getUsername()); //로그인 정ㅈㅅ아완료


            //authentication 객체가 session 영역에 저장을해야하고 그 방법이 return 해주면됨
            //리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
            //굳이 JWT 토큰을 사용하면ㅅ ㅓ세션을 만들 이유가 없음 .근데 단지 구너한 처리 때문에
            //session에 넣어 줍니다.


            return  authentication;

        }catch (IOException e){
            e.printStackTrace();
        }

        //2.정상인지 로그인 시도를 해보는 것
        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출
        //loadUserByUseranme()함수 실행 됨

        //3.PrincipalDetails를 세션에 담고 --ROL_USER 이런 권한 관리를 위해 세션 사용
        //굳이 권한 관리 안할꺼면 사용할 필요 없다

        //4.JWT토큰을 만들어서 사용하면 됨 - 즉 응답을 하면 됨

        return null;
    }

    //attemptAuthentication() 실행 후 인증이 정상 완료시 successfulAuthentication 함수 실행됨
    //JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication 실행됨 : 인증이 완료 되었다.");
        PrincipalDetails principalDetails=(PrincipalDetails)authResult.getPrincipal();

        //RES방식으 아니고 Hash 암호 방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰") //토큰 이름
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) //만료 시간 -10분이 적당
                .withClaim("id", principalDetails.getUser().getId()) //넣고 싶은 값
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));
                //HMAC은 secret key를가지고 있어야 함

                                                //한 칸 띄워야 함
        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
