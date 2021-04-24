# **기계학습 Challenge**
1. **대회목표**: 한정된 파라미터를 이용해서 알려지지 않은 데이터셋의 인식 성능을 높여라!

2. **세부 프로토콜**

   데이터셋: 알려지지 않는 데이터 셋
   
   네트워크 파라미터: weight의 숫자가 300K 이하인 딥러닝 모델 

   아키텍쳐: 자유

   학습알고리즘: 자유

   딥러닝 프레임워크: PyTorch 권장, TensorFlow등 다른 프레임워크도 사용 가능

   외부데이터: 사용하면 안됨

3. **순위산정:** 알려지지 않은 테스트 데이터 셋의 Top-1 Accuracy

4. **팀 구성**: 기본 1인 1팀, 중간 1차 발표 이후 최대 2인까지 팀 구성 가능

5. **시상**: 1위 n만원, 2/3위 각각 n만원 상금 지급

6. **대회진행**

   |     날짜      |      일정       |
   | :-----------: | :-------------: |
   |     시작      | 2021년 1월 11일 |
   | 중간 1차 발표 | 2021년 2월 1일  |
   | 중간 2차 발표 | 2021년 2월 22일 |
   | 최종결과 발표 | 2021년 3월 8일  |

7. **최종 결과 산출 방법:** 2021년 2월 22일의 Accuracy의 20% + 2021년 3월 8일의 Accuracy의 80%


## 퍼블릭 랭킹

  
- Total Score가 아직 업데이트되지 않았습니다. 
 - 다음 업데이트 일정은 중간 점수 집계(2021-05-10) 입니다.
  
**현재 랭킹 1위는 hey 입니다. 평균 accuracy는 40.0% 입니다.**
|Ranking|Name|Penalty|Accuracy(%)|Last Submission|Total Submission Count|Total Score(%)|
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
|1|hey|0|40.0|2021-04-24 17:42:36.630780+09:00|2|0.0|


**정확도는 소숫점 5자리 까지 출력됩니다.**
**Time zone is seoul,korea (UTC+9:00)**
## 퍼블릭 랭킹 제출 방법

본인이름의 폴더 안에 테스트 데이터 셋을 예측한 결과값을 암호화해서 제출하면 됨.

Example) 

1. 예측 파일 만들기. 다음과 같은 예측 파일이 있다고 가정 `ans.txt`

   ```tex
   1 9
   2 8
   3 10
   4 99
   5 98
   6 70
   7 18
   8 33
   ```

2. 예측 파일(`ans.txt`)과 본인의 키를 `Encrypt` 폴더에 넣고 `Encrypt.py`를 실행 시켜서 암호화한 예측 파일(`ans.json`)을 만들어 낸 다. 생성한 파일을 본인의 이름으로 된 폴더안(`submission/hankyul`)에 넣고 커밋 후 푸쉬하면 됨.

   ```python
   # 1.이메일을 통해서 전달 받은 키 파일의 경로 입력
   key_path = "key.pem"
   # 2. 예측한 결과를 텍스트 파일로 저장했을 경우 리스트로 다시 불러오기
   # 본인이 원하는 방식으로 리스트 형태로 예측 값을 불러오기만 하면 됨(순서를 지킬것)
   raw_ans_path = "ans.txt"
   ans = read_txt(raw_ans_path)
   # 3. 암호화된 파일을 저장할 위치
   encrypt_ans_path = "ans.json"
   # 4. 암호화!(pycrytodome 설치)
   encrypt_data(key_path, ans, encrypt_ans_path)
   ```




