Northgate Retail Ltd — ערכת נתונים לחקירה
==============================================

קראו את הקובץ הזה לפני שאתם מעלים משהו ל-Splunk.


1. מה יש בערכה
----------------------------------------------
שבעה מקורות לוג ושני קבצי lookup. הכל CSV עם שורת כותרת.

  קובץ                        sourcetype   אזור זמן  שורות
  northgate_winevent.csv      winevent     UTC+3    11,526
  northgate_fileaudit.csv     fileaudit    UTC      35,528
  northgate_vpn.csv           vpn          UTC      540
  northgate_proxy.csv         proxy        UTC      4,838
  northgate_weblog.csv        weblog       UTC      4,970
  northgate_cloudaudit.csv    cloudaudit   UTC      689
  northgate_backup.csv        backup       UTC      103
  identity.csv                lookup       —         34
  assets.csv                  lookup       —         79

סך הכל 58,194 אירועים.


2. אזורי זמן — קראו את הסעיף הזה פעמיים
----------------------------------------------
winevent כתוב ב-UTC+3.
כל שאר המקורות כתובים ב-UTC.
אין עמודת offset באף קובץ, ואף אחד לא יסמן לכם את זה.

כשאתם בונים ציר זמן משולב אתם מתרגמים את winevent בעצמכם.
אם אתם רואים פעולה שמופיעה אחרי התוצאה של עצמה — זו לא תקלה בנתונים.


3. העלאה ל-Splunk
----------------------------------------------
לכל אחד משבעת קבצי הלוג:

  1. Settings  >  Add Data  >  Upload
  2. בחרו את הקובץ
  3. Set Source Type — אם העמודות לא מופיעות בתצוגה המקדימה,
     בחרו Structured  >  csv
  4. Save As — תנו לו את שם ה-sourcetype מהטבלה שלמעלה
  5. Index: northgate   (צרו אותו אם הוא לא קיים)

שני קבצי ה-lookup עולים בדרך אחרת:

  Settings  >  Lookups  >  Lookup table files      העלו את identity.csv ואת assets.csv
  Settings  >  Lookups  >  Lookup definitions      הגדירו definition לכל אחד מהם

בלי ה-definition הפקודה lookup לא תמצא אותם.


4. Time picker
----------------------------------------------
בחרו All time.
הנתונים מסתיימים ב-2026-08-20 11:58:44 ומתחילים ב-2026-05-23 01:02:22.
ברירת המחדל של הזמן ב-Splunk תחזיר לכם אפס תוצאות.


5. בדיקות שפיות — הריצו אותן לפני שאתם מתחילים לחקור
----------------------------------------------
index=northgate | stats count by sourcetype

  מצפים ל:
    winevent    11,526
    fileaudit   35,528
    vpn         540
    proxy       4,838
    weblog      4,970
    cloudaudit  689
    backup      103

index=northgate | stats count

  מצפים ל: 58,194

index=northgate sourcetype=fileaudit | head 3 | table _time actor object_path

  מצפים לשלוש שורות עם שלוש עמודות.
  אם אתם מקבלים שורה אחת של טקסט — הקובץ לא נקרא כ-CSV.
  חזרו לסעיף 3 שלב 3 ובחרו Structured > csv.

| inputlookup identity.csv | stats count

  מצפים ל: 34

| inputlookup assets.csv | stats count

  מצפים ל: 79

index=northgate | stats min(_time) as first max(_time) as last

  שימו לב שהערך המקסימלי יגיע מ-winevent ולכן ייראה מאוחר יותר.
  זה מכוון. חזרו לסעיף 2.


6. הערה אחרונה
----------------------------------------------
שמות השדות כאן הם לא CIM ולא זהים בין המקורות.
אל תניחו שם שדה — בדקו אותו.
`| fieldsummary` הוא חבר שלכם.
