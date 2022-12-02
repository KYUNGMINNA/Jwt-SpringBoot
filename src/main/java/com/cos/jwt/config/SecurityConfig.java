package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserRepository userRepository;

    private final CorsFilter corsFilter;
    //필터를 만드는 방식

    //@Configuration
    //public class WebConfig implements WebMvcConfigurer
    //이렇게 하는게 더 나음




    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        //시큐리티 필터 체인에 거는 방법 -- SecurityContextPersistenceFilter필터가 시큐리티 필터 중 가장 앞에 있음
        //시큐리티 필터가 돌기 전에 MyFilter3()이 돌게 하기 위한 코드
        //시큐리티 필터에 적용이 안되기 때문에 위의 처럼 사용해야함 --오류 발생하기 때문
        //내가 만든 필터가 시큐리티 필터보다 빨리 적용시키려면 위의 코드 처럼 해야 함



        http.csrf().disable();

        //세션을 사용하지 않겠다라는 의미 sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter)  //@CrossOrigin (인증 XX)방식 이고 , 이 방법은 필터에 등록 인증O
                .formLogin().disable() //form태그 만들어서 로그인 안한다 라는 의미 -시큐리티 기본 login페이지 동작안함
                .httpBasic().disable() //기본 인증방식도 안쓰겠다
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

        //세션과 ,httmlBasic 방식을 안쓰고 JWT 토큰 방식을 쓰기 위함 이다 !!


        //WebSecurityConfigurerAdapter는 authenticationManager()를 갖고 있음 !!!






    }
}
