-- boards 테이블 데이터
insert into boards(board_no,title,content,writer,category)
  values(100,'제목1','내용1',101,1);
insert into boards(board_no,title,content,writer,category)
  values(101,'제목2','내용2',102,1);
insert into boards(board_no,title,content,writer,category)
  values(102,'제목3','내용3',102,1);
insert into boards(board_no,title,content,writer,category)
  values(103,'제목4','내용4',104,1);
insert into boards(board_no,title,content,writer,category)
  values(104,'제목5','내용5',104,1);
insert into boards(board_no,title,content,writer,category)
  values(105,'제목5','내용5',104,1);
insert into boards(board_no,title,content,writer,category)
  values(106,'제목5','내용5',104,1);
insert into boards(board_no,title,content,writer,category)
  values(107,'제목5','내용5',104,1);
 insert into boards(board_no,title,content,writer,category)
    values(108,'제목5','내용5',104,1);
insert into boards(board_no,title,content,writer,category)
  values(109,'제목5','내용5',104,1);
insert into boards(board_no,title,content,writer,category)
  values(110,'제목5','내용5',104,1);
insert into boards(board_no,title,content,writer,category)
  values(111,'제목5','내용5',104,1);
  insert into boards(board_no,title,content,writer,category)
    values(112,'제목5','내용5',104,1);
    insert into boards(board_no,title,content,writer,category)
      values(113,'제목5','내용5',104,1);
      insert into boards(board_no,title,content,writer,category)
        values(114,'제목5','내용5',104,1);
        insert into boards(board_no,title,content,writer,category)
          values(115,'제목5','내용5',104,1);





-- board_files 테이블 데이터
insert into board_files(file_no,file_path,board_no)
  values (1,'a1.gif',1 ),(2,'a2.git',1),(3,'a3.git',1),
  (4,'b1.gif',2 ),(5,'b2.git',2),
  (6,'c1.git',4),(7,'c2.gif',4),(8,'c3.git',4),(9,'c4.git',4),
  (10,'d1.gif',5);

insert into board_files(file_no,file_path,board_no)
  values (15,'aaa.gif',2),(16,'aaab.gif',2),(17,'aaac.gif',2)

-- assignment 테이블 데이터
insert into assignments(title,content,deadline)
  values('과제1','내용1','2023-11-2');
insert into assignments(title,content,deadline)
  values('과제2','내용2','2023-11-3');
insert into assignments(title,content,deadline)
  values('과제3','내용3','2023-11-4');
insert into assignments(title,content,deadline)
  values('과제4','내용4','2023-11-5');
insert into assignments(title,content,deadline)
  values('과제5','내용5','2023-11-6');

-- members 테이블 데이터
insert into members(member_no,email,name,password,created_date)
  values(101,'user1@test.com','이름1',sha2('1111',256),'2024-01-01');
insert into members(member_no,email,name,password,created_date)
  values(102,'user2@test.com','이름2',sha2('1111',256),'2024-02-01');
insert into members(member_no,email,name,password,created_date)
  values(103,'user3@test.com','이름3',sha2('1111',256),'2024-03-01');
insert into members(member_no,email,name,password,created_date)
  values(104,'user4@test.com','이름4',sha2('1111',256),'2024-04-01');
insert into members(member_no,email,name,password,created_date)
  values(105,'user5@test.com','이름5',sha2('1111',256),'2024-05-01');
