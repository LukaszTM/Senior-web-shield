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
2. Każde zapytanie DNS jest sprawdzane na **wbudowanej liście ~300 sieci reklamowych,
   trackerów i domen znanych ze scamu** (w tym polskich). Zablokowana domena dostaje
   odpowiedź „nie istnieje" (NXDOMAIN) — reklama w aplikacji po prostu się nie ładuje.
3. Pozostałe zapytania są przekazywane do **AdGuard DNS** (94.140.14.14) — publicznego
   serwera DNS, który dodatkowo blokuje reklamy, trackery i strony wyłudzające dane.
   To druga warstwa ochrony, aktualizowana na bieżąco po stronie serwera.

## Funkcje dla seniora

- **Jeden wielki przycisk** — zielony włącza, czerwony wyłącza. Nic więcej.
- **Duże czcionki i kontrastowe kolory** (WCAG), proste komunikaty po polsku.
- **Licznik zablokowanych reklam** (dzisiaj / łącznie) — widać, że ochrona działa.
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

## Instalacja u seniora (dla opiekuna)

1. Zainstaluj APK i uruchom aplikację.
2. Naciśnij **WŁĄCZ OCHRONĘ** i zatwierdź systemowe okienko zgody na VPN („OK").
3. Na Androidzie 13+ zezwól na powiadomienia (żeby ochrona nie była ubijana w tle).
4. Warto dodatkowo: Ustawienia → Aplikacje → Shield ADV → Bateria →
   **Bez ograniczeń** (żeby system nie zatrzymywał ochrony).
5. Opcjonalnie: Ustawienia → Sieć → VPN → Shield ADV → **Stały VPN**
   (ochrona nie do wyłączenia przypadkiem).

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
Jedyny ruch wychodzący to zwykłe zapytania DNS do publicznego resolvera AdGuard DNS
(polityka prywatności: adguard-dns.io). Licznik blokad jest przechowywany wyłącznie
lokalnie na telefonie.
