## 🚗 Huoltorapsa

Kevyt ja helppokäyttöinen työkalu ajoneuvojen huoltoraporttien luomiseen, hallintaan ja tulostamiseen. Sovellus toimii paikallisesti selaimessa ja käyttää Python-taustajärjestelmää tietojen tallennukseen.

> [!WARNING]
> <pre>This project is FULLY AI CODED, no line has been reviewed 
> by qualified personnel. It seems to work but fatal bugs and 
> performance issues are more than likely.
> Made by Gemini Pro & Codex 5.3</pre>

## 🌟 Ominaisuudet

- Raporttien hallinta: Luo, muokkaa ja arkistoi huoltoraportteja digitaalisesti.
- Tulostus: Siisti, A4-optimoitu tulostusnäkymä asiakkaalle annettavaksi.
- Liitteet: Liitä raporttiin kuvia (esim. vauriokohdista tai vaihdetuista osista).
- Älykäs haku: Hakee asiakkaan ja ajoneuvon tiedot (VIN, malli) automaattisesti rekisterinumeron perusteella aiemmista raporteista.
- Mukautettavuus:
    - Muokkaa huoltokohtien listaa (esim. jarrut, nesteet) suoraan asetuksista, ja lisää tarkempia lisätietoja. Raportti tunnistaa muutokset ja tarjoaa päivitysmahdollisuuden. Poistuneille kohteille voi etsiä vastineet raportilla.
    - Lisää yrityksen logo ja yhteystiedot tulosteisiin.
    - Huoltosetit: Luo huoltosettejä ja käytä niitä raportilla yhdellä painalluksella.

- Arkisto: Selaa vanhoja raportteja hakusanoilla (rek.nro, asiakas, pvm).
- Kalenteri: Näytä raportit kalenterinäkymässä ja luo huoltovarauksia tulevaisuuteen.

## 🚀 Käyttöönotto

Sovellus on kevyt eikä vaadi asennuksia. Tarvitset vain Python 3:n, esim. [Microsoft Storesta](https://apps.microsoft.com/detail/9pnrbtzxmb4z).

**Windows-käyttäjät:**

Voit käyttää mukana tulevaa run.cmd-tiedostoa (Ei toimi **Windows S Mode**, käytä manuaalista tapaa).

1. [Lataa sovellus ZIP-tiedostona](https://github.com/hiatsu0/Huoltorapsa/archive/refs/heads/main.zip) ja pura haluamaasi paikkaan.
2. Tuplaklikkaa run.cmd.
3. Skripti tarkistaa onko Python asennettu ja asentaa sen tarvittaessa automaattisesti.
4. Palvelin käynnistyy, luo tietokannat ja avaa selainnäkymän.

**Manuaalinen:**

1. Lataa tiedostot kansioon.
2. Avaa komentorivi/terminaali kansiossa.

   Jos komentorivi ei ole käytettävissä (**Windows S Mode**), luo uusi pikakuvake jossa ao. komento.
4. Käynnistä palvelin komennolla: <code>python server.py</code> (tai <code>python3 server.py</code>)
5. Ellei selainnäkymä aukea automaattisesti, mene osoitteeseen: http://localhost:8000

Tietokannat (maintenance.db ja attachments.db) luodaan automaattisesti ohjelman juureen ensimmäisellä käynnistyksellä.

## ⚙️ Asetukset

Sovelluksen Asetukset-näkymässä voit:

1. Ladata yrityksen logon.
2. Kirjoittaa yrityksen tiedot, jotka tulostuvat raportin yläosaan.
3. Muokata huoltotehtäviä visuaalisella editorilla (tai suoraan JSON-dataa muokaten).
4. Luoda ja hallita huoltosettejä.
5. Muuttaa statustekstit (Suoritettu / Ei tehty / Ei sisälly)
6. Valita korostusvärin ja tumman tai vaalean teeman.
7. Ottaa salasanasuojauksen käyttöön (salasanan nollaus tarvittaessa: <code>python3 resetpw.py</code>).
8. Ladata asetuksista ja merkinnöistä varmuuskopion.
9. Päivittää sovelluksen uusimman version tästä reposta.


## 🛠️ Tekninen toteutus

- Frontend: HTML5, CSS3, Vanilla JavaScript (ei vaadi node.js-ympäristöä).
- Backend: Python (Standard Library http.server). **Vain paikalliskäyttöön tai sisäverkkoon, ei sovellu julkiseen internetiin!**
- Tietokanta: SQLite3 (sisäänrakennettu, ei vaadi erillistä palvelinta).

## 📄 Lisenssi

AGPLv3 (Makkesoft 2026)

## 📷 Kuvakaappauksia

*Raportin täyttö ja tulostus:*

![report-edit](https://github.com/user-attachments/assets/a4c4012b-fda4-443f-9c9a-d163f6e2160e)


*Kalenterinäkymä ja asetukset:*

![kalenteri, asetukset](https://github.com/user-attachments/assets/a8e4bd8b-d805-4eb4-af38-cb4417d05e7d)

