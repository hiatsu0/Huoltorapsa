## 🚗 Huoltorapsa

Kevyt ja helppokäyttöinen työkalu ajoneuvojen huoltoraporttien luomiseen, hallintaan ja tulostamiseen. Sovellus toimii paikallisesti selaimessa ja käyttää Python-taustajärjestelmää tietojen tallennukseen.

> **WARNING & DISCLOSURE :**
> <pre>This project is FULLY AI coded, no line has been reviewed by qualified personnel. 
> It seems to work but fatal bugs and performance issues are more than likely.
> Made by Gemini Pro & Codex 5.3</pre>

## 🌟 Ominaisuudet

- Raporttien hallinta: Luo, muokkaa ja arkistoi huoltoraportteja digitaalisesti.
- Tulostus: Siisti, A4-optimoitu tulostusnäkymä asiakkaalle annettavaksi.
- Liitteet: Liitä raporttiin kuvia (esim. vauriokohdista tai vaihdetuista osista).
- Älykäs haku: Hakee ajoneuvon tiedot (VIN, malli) automaattisesti rekisterinumeron perusteella aiemmista raporteista.
- Mukautettavuus:
    - Muokkaa huoltokohtien listaa (esim. jarrut, nesteet) suoraan asetuksista, ja lisää tarkempia lisätietoja. Raportti tunnistaa muutokset ja tarjoaa "Päivitä"-toiminnon. Poistuneille kohteille voi etsiä vastineet raportilla.
    - Lisää yrityksen logo ja yhteystiedot tulosteisiin.
    - Huoltosetit: Luo huoltosettejä ja käytä niitä raportilla yhdellä painalluksella.

- Arkisto: Selaa vanhoja raportteja hakusanoilla (rek.nro, asiakas, pvm).

## 🚀 Käyttöönotto

Sovellus on kevyt eikä vaadi asennuksia. Tarvitset vain Python 3:n.

**Windows-käyttäjät (Helppo tapa):**

Voit käyttää mukana tulevaa run.cmd-tiedostoa (Ei toimi **Windows S Mode**, käytä manuaalista tapaa).

1. Tuplaklikkaa run.cmd.
2. Skripti tarkistaa onko Python asennettu ja asentaa sen tarvittaessa automaattisesti.
3. Palvelin käynnistyy.

**Manuaalinen asennus:**

1. Lataa tiedostot kansioon.
2. Avaa komentorivi/terminaali ko. kansiossa.
3. Käynnistä palvelin komennolla: <code>python server.py</code>
4. Avaa selain ja mene osoitteeseen: http://localhost:8000

Tietokannat (maintenance.db ja attachments.db) luodaan automaattisesti ohjelman juureen ensimmäisellä käynnistyksellä.

## ⚙️ Asetukset

Sovelluksen Asetukset-näkymässä voit:

1. Ladata yrityksen logon.
2. Kirjoittaa yrityksen tiedot, jotka tulostuvat raportin yläosaan.
3. Muokata huoltotehtäviä visuaalisella editorilla (tai suoraan JSON-dataa muokaten).
4. Luoda ja hallita huoltosettejä.
5. Muuttaa statustekstit (Suoritettu / Ei tehty / Ei sisälly)
6. Valita korostusvärin.
7. Ottaa salasanasuojauksen käyttöön (salasanan nollaus tarvittaessa: <code>python3 resetpw.py</code>).


## 🛠️ Tekninen toteutus

- Frontend: HTML5, CSS3, Vanilla JavaScript (ei vaadi node.js-ympäristöä).
- Backend: Python (Standard Library http.server).
- Tietokanta: SQLite3 (sisäänrakennettu, ei vaadi erillistä palvelinta).

## 📄 Lisenssi

AGPLv3 (Makkesoft 2026)
