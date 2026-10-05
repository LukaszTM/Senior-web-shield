# Shield ADV 🛡️

Aplikacja na Androida, która **blokuje natarczywe reklamy w aplikacjach i grach** na
telefonie — zaprojektowana specjalnie **z myślą o seniorach**. Chroni przed agresywnymi
reklamami, które wyłudzają kliknięcia, pieniądze i dane osobowe.

## Jak to działa

Aplikacja nie wymaga roota. Korzysta z mechanizmu **lokalnego VPN** systemu Android
(tak jak znane blokery DNS66 czy Blokada):

1. Tworzy na telefonie lokalny tunel VPN, przez który przechodzą **wyłącznie zapytania
   DNS** (tłumaczenie nazw domen na adresy). Pozostały ruch (strony, wideo, rozmowy)
   idzie normalną drogą — **nic nie jest wysyłane na żaden zewnętrzny serwer VPN**.
2. Każde zapytanie DNS jest sprawdzane **lokalnie, na telefonie**, na trzech listach:
   - wbudowanej (~300 sieci reklamowych, trackerów i domen scamowych, z kategoriami),
   - **liście ostrzeżeń CERT Polska** (hole.cert.pl) — domeny używane w oszustwach
     wymierzonych w Polaków: fałszywe dopłaty, paczki, banki, SMS-y z linkami,
   - **filtrze AdGuard DNS** — ten sam zestaw reguł reklam/trackerów, którego używa
     publiczny serwer AdGuard (z obsługą wyjątków `@@`).

   Listy są pobierane po włączeniu ochrony i odświeżane co ok. 24 h. Zablokowana domena
   dostaje odpowiedź „nie istnieje" (NXDOMAIN) — reklama po prostu się nie ładuje.
3. Pozostałe zapytania są przekazywane do **serwera DNS operatora** (tego, z którego
   telefon korzystałby bez VPN — wykrywanego automatycznie dla aktualnej sieci), dzięki
   czemu dobór serwerów CDN (YouTube, Facebook, aktualizacje) i opóźnienia są takie same
   jak bez aplikacji. **AdGuard DNS** (94.140.14.14) służy wyłącznie jako zapas, gdy
   serwer operatora nie odpowiada.

## Funkcje dla seniora

- **Jeden wielki przycisk** — zielony włącza, czerwony wyłącza. Nic więcej.
- **Duże czcionki i kontrastowe kolory** (WCAG), proste komunikaty po polsku.
- **Licznik zablokowanych reklam** (dzisiaj / łącznie) — widać, że ochrona działa.
- **Zakładka „Zablokowane"** — lista zatrzymanych stron z **oceną bezpieczeństwa**
  (niskie / średnie / wysokie ryzyko), prostym wyjaśnieniem, liczbą blokad i czasem
  ostatniej. Ocena wynika z kategorii domeny na wbudowanej liście (`[ads]`, `[tracking]`,
  `[scam]`); strony zatrzymane przez AdGuard DNS są oznaczane jako „Podejrzana".
- **Pauza zamiast wyłączania** — czerwony przycisk proponuje „Wstrzymaj na 15 minut"
  (ochrona wraca sama); „Wyłącz na stałe" można zabezpieczyć **PIN-em opiekuna**.
- **Strażnik ochrony** — gdy system ubije serwis, aplikacja włącza go ponownie przy
  otwarciu, cyklicznie sprawdza w tle i w razie potrzeby wysyła powiadomienie
  „Ochrona przestała działać"; zakładka **Opiekun** pozwala jednym dotknięciem wyłączyć
  oszczędzanie baterii dla aplikacji i otworzyć ustawienia stałego VPN.
- **Automatyczny start po restarcie telefonu** — senior nie musi niczego pamiętać.
- **Stała ikona klucza** na pasku statusu = ochrona aktywna.
- Brak reklam, brak opłat, brak zbierania jakichkolwiek danych.

## Budowanie

Wymagany Android Studio (lub Android SDK z platformą 34):

```bash
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Minimalna wersja Androida: **8.0 (API 26)**.

### Podpisane wydanie (release)

APK debugowy jest podpisany kluczem testowym, przez co Google Play Protect może go
blokować jako „aplikację nieznanego dewelopera". Wydania powinny być podpisane własnym,
stałym kluczem:

```bash
keytool -genkeypair -v -keystore shield-adv-release.jks -alias shieldadv \
  -keyalg RSA -keysize 2048 -validity 10000
```

Klucz przechowuj bezpiecznie — aktualizacja aplikacji wymaga tego samego klucza.
W GitHub (Settings → Secrets and variables → Actions) ustaw sekrety:
`SHIELD_KEYSTORE_BASE64` (wynik `base64 -w0 shield-adv-release.jks`),
`SHIELD_KEYSTORE_PASSWORD`, `SHIELD_KEY_ALIAS` (`shieldadv`), `SHIELD_KEY_PASSWORD`.
Workflow zbuduje wtedy dodatkowo artefakt **ShieldADV-release-apk**. Lokalnie:

```bash
SHIELD_KEYSTORE_PATH=/sciezka/shield-adv-release.jks SHIELD_KEYSTORE_PASSWORD=... \
SHIELD_KEY_ALIAS=shieldadv SHIELD_KEY_PASSWORD=... ./gradlew assembleRelease
```

## Instalacja u seniora (dla opiekuna)

1. Zainstaluj APK i uruchom aplikację.
2. Naciśnij **WŁĄCZ OCHRONĘ** i zatwierdź systemowe okienko zgody na VPN („OK").
3. Na Androidzie 13+ zezwól na powiadomienia (żeby ochrona nie była ubijana w tle).
4. Warto dodatkowo: Ustawienia → Aplikacje → Shield ADV → Bateria →
   **Bez ograniczeń** (żeby system nie zatrzymywał ochrony).
5. Opcjonalnie: Ustawienia → Sieć → VPN → Shield ADV → **Stały VPN**
   (ochrona nie do wyłączenia przypadkiem).

## Wydajność

Przez tunel przechodzą tylko zapytania DNS, więc przepustowość nie jest ograniczana.
Żeby nie było też odczuwalnych opóźnień:

- VPN jest oznaczony jako **sieć nielimitowana** (`setMetered(false)`) — inaczej Android
  traktuje połączenie jak taryfowe i ogranicza jakość wideo, pobieranie i synchronizację.
- Zapytania idą do **DNS operatora** przez **jedno współdzielone gniazdo** przypięte do
  sieci bazowej, z dowolną liczbą zapytań w locie; brak odpowiedzi po 1 s powoduje
  ponowienie do kolejnego serwera (operator → AdGuard), wygrywa pierwsza odpowiedź.
  Zewnętrzny resolver potrafi kierować do dalszych węzłów CDN niż DNS operatora —
  stąd wybór serwera operatora jako domyślnego.
- **Pamięć podręczna DNS** (do 2000 wpisów, z poszanowaniem TTL) obsługuje powtórne
  zapytania bez ruchu sieciowego.
- Próby TCP/TLS do lokalnego serwera DNS (np. sonda „Prywatny DNS: automatycznie"
  w Androidzie) dostają natychmiast **TCP RST** zamiast czekać na timeout.

## Ograniczenia (uczciwie)

- **Reklamy YouTube i reklamy w wynikach Google nie są blokowane** — są serwowane
  z tych samych domen co treść, więc blokada DNS ich nie odróżni.
- Jeśli w telefonie ustawiono **Prywatny DNS** (DoT), niektóre aplikacje mogą go
  omijać — w razie potrzeby ustaw Prywatny DNS na „Wyłączony".
- Może działać tylko **jeden VPN naraz** — włączenie innego VPN wyłączy ochronę
  (aplikacja to wykryje i zaktualizuje status).
- Niektóre aplikacje bankowe zgłaszają ostrzeżenie przy aktywnym VPN — to normalne;
  ruch bankowy **nie przechodzi** przez tę aplikację (filtrowany jest tylko DNS).

## Prywatność

Aplikacja nie ma żadnego serwera, nie zbiera i nie wysyła żadnych danych.
Jedyny ruch wychodzący to zwykłe zapytania DNS do serwera operatora (jak bez aplikacji),
awaryjnie do AdGuard DNS (polityka prywatności: adguard-dns.io), oraz pobieranie list
blokad z adguardteam.github.io i hole.cert.pl. Licznik i lista blokad są przechowywane
wyłącznie lokalnie na telefonie.
