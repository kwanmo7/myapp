package bitcamp.myapp.vo;

public class ConstVO {

  // 폰트 RESET
  public static final String RESET = "\u001B[0m";
  // 폰트 변경 - 붉은색
  public static final String ANSI_RED = "\033[0;31m";
  // 폰트 변경 - 붉은색 볼드체
  public static final String ANSI_BOLD_RED = "\033[1;31m";

  public static final String ANSI_BOLD = "\033[1m";

  public static final String[] MAIN_MENU = {
      ANSI_BOLD_RED + "[과제관리 시스템]" + RESET,
      "1. 과제",
      "2. 게시글",
      "3. 회원",
      "4. 가입인사",
      "5. 도움말",
      ANSI_RED + "0. 종료" + RESET};
  public static final String[] BOARD_MENU = {
      "1. 등록",
      "2. 조회",
      "3. 변경",
      "4. 삭제",
      "5. 목록",
      "0. 이전"
  };
  public static final String[] ASSIGNMENT_MENU = {
      "1. 등록",
      "2. 조회",
      "3. 변경",
      "4. 삭제",
      "5. 목록",
      "0. 이전"
  };
  public static final String[] MEMBER_MENU = {
      "1. 등록",
      "2. 조회",
      "3. 변경",
      "4. 삭제",
      "5. 목록",
      "0. 이전"
  };
}
