https://gemini.google.com/app/45a612e892648f5b?hl=id
# WriteUp: Learn Typing

## Informasi Challenge

  * **Nama:** Learn Typing
  * **Kategori:** Reverse Engineering / Web
  * **Author:** aria
  * **Difficulty:** Easy
  * **Deskripsi:** Website ini menantang pengguna untuk mengetik dengan kecepatan 120-150 WPM dan akurasi 100% dalam waktu 50 detik.
  * **Hint:** "Web ini berjalan di browser kamu sendiri..."

## Analisis

Setelah membuka website, terdapat tes kecepatan mengetik yang sangat sulit dilakukan secara manual. Karena hint menyebutkan web berjalan di browser (client-side), langkah pertama adalah memeriksa source code JavaScript.

Pada file `_0x8d3e9c.js`, ditemukan sebuah fungsi bernama `_0xsr` yang menangani logika akhir permainan:

```javascript
// Show results
function _0xsr(_0xwpm, _0xacc, _0xtu) {
  _0xel._0xrp.classList.remove("_0xhd");

  // Validasi WPM (120 - 150)
  const _0xwv = _0xwpm >= _0xcfg._0xmin && _0xwpm <= _0xcfg._0xmax;
  // Validasi Akurasi (100)
  const _0xav = _0xacc === _0xcfg._0xacc;

  if (_0xwv && _0xav) {
    _0xel._0xrt.textContent = "🎉 Selamat!";
    // ... code ...
    // Menampilkan Flag
    _0xel._0xfd.textContent = `🚩 Flag: ${_0xdf()}`;
  } else {
    // ... logika gagal ...
  }
}
```

Terlihat bahwa fungsi ini menerima parameter `_0xwpm` (Words Per Minute), `_0xacc` (Accuracy), dan `_0xtu` (Time). Jika parameter yang dimasukkan memenuhi syarat, fungsi `_0xdf()` akan dipanggil untuk mendeskripsi flag.

## Langkah Penyelesaian (Exploitation)

Kita dapat memanipulasi alur program dengan memanggil fungsi tersebut secara langsung melalui Console Browser (Developer Tools), melewati proses mengetik sepenuhnya.

1.  Buka halaman challenge.
2.  Buka **Inspect Element** dan masuk ke tab **Console**.
3.  Panggil fungsi `_0xsr` dengan nilai yang memenuhi syarat (WPM antara 120-150, Akurasi 100).
    Payload:
    ```javascript
    _0xsr(135, 100, 20)
    ```
4.  Tekan **Enter**. Website akan merespon seolah-olah kita telah menyelesaikan tes dengan nilai tersebut dan menampilkan flag.

## Hasil

Setelah command dieksekusi, flag muncul di layar:

```text
FGTE{dont_type_it_reverse_it}
```
