package bitcamp.myapp.security05;

import bitcamp.myapp.service.MemberService;
import bitcamp.myapp.vo.Member;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MyUserDetailsService03 implements UserDetailsService {
  private static final Log log = LogFactory.getLog(MyUserDetailsService03.class);

  // DBMB에서 사용자 정보를 찾아주는 service 객체
  private MemberService memberService;

  public MyUserDetailsService03(MemberService memberService) {
    this.memberService = memberService;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    Member member = memberService.get(username);
    if(member == null){
      throw new UsernameNotFoundException("해당 사용자가 존재하지 않습니다.");
    }

    log.debug(String.format("member : %s", member));

    // DB에 해당 이메일을 가진 사용자가 존재하는 경우
    // Spring Security에게 UserDetails 객체를 보내 줌
    // 클라이언트가 보낸 username/password를 비교하여 로그인 처리를 수행하게 됨
    return User.builder()
        .username(member.getEmail()) // DB에서 받은 email
        .password(member.getPassword()) // DB에서 받은 password
        .roles("USER")
        .build();
  }
}
