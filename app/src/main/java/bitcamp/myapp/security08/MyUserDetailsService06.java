package bitcamp.myapp.security08;

import bitcamp.myapp.service.MemberService;
import bitcamp.myapp.vo.Member;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MyUserDetailsService06 implements UserDetailsService {
  private static final Log log = LogFactory.getLog(MyUserDetailsService06.class);

  // DBMB에서 사용자 정보를 찾아주는 service 객체
  private MemberService memberService;

  public MyUserDetailsService06(MemberService memberService) {
    this.memberService = memberService;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    Member member = memberService.get(username);
    if(member == null){
      throw new UsernameNotFoundException("해당 사용자가 존재하지 않습니다.");
    }

    log.debug(String.format("member : %s", member));

    MemberUserDetails01 userDetails = new MemberUserDetails01();
    userDetails.setNo(member.getNo());
    userDetails.setName(member.getName());
    userDetails.setEmail(member.getEmail());
    userDetails.setPassword(member.getPassword());
    userDetails.setPhoto(member.getPhoto());

    return userDetails;
  }
}
