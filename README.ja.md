# Momiji
Python向けの強力なWebアプリケーションフレームワークとサーバー

## Momijiとは
MomijiはPython向けのWebアプリケーションフレームワークとそのサーバーです。

Momijiは簡素かつ強力であることを重視して開発されました。
レスポンス圧縮やコンテンツの最小化など一般的にWebサーバーに必要とされる機能を持ちつつ、他の余分な機能はありません。

## 特徴
Momijiはそのシンプルな構造から、比較的簡単に使用できます。

例えばただ単に「Hello, World!」と返すサーバーであれば、ほんの数行のコードで作れます:

```python
from momiji import Server, App, Response

class MyApp(App):
    async def on_request(self, request):
        return Response("Hello, World!".encode(), content_type="text/plain")

if __name__ == "__main__":
    server = Server(MyApp())
    server.run()
```

Server/App/Response/Responseのような構造はASGIから着想を得ています。

## (おそらく)よくある質問

### シンプルすぎる。なんだこれ！
はい、すごくシンプルです。何か問題でも？

### [Aki](https://github.com/nercone-momiji/aki/)というリポジトリを見つけました。Momijiと関係があるようですが...これは何でしょうか？
Momijiはとてもシンプルですが、FastAPIのような「エンドポイントを定義して自動でルーティングしてくれる」ような賢い機能はありません。

AkiはそんなMomijiをFastAPIと同じ感覚で使用できるようにするためのライブラリで、開発予定です。

### `pyproject.toml`を読み、aioquicが本家ではなく`nercone-forks/aioquic`を使用するように設定されていることに気づきました。これはなぜですか？
aioquicはPQC(Post-quantum Cryptography, ポスト量子暗号)に対応していません。
しかし、(Harvest now, Decrypt later攻撃のことを知り)私は全てのWebサイトがPQCに対応すべきと考えているため、aioquicをフォークしPQCに対応させました。

本家にはプルリクエストを送信済みで、マージされたら本家に変更する予定です。

なお、Momijiの開発時にqh3というフォークを見つけました。そちらのフォークでもPQCに対応しているようで、本家の開発も停滞しているため、マージされそうになければqh3に変更する予定です。

### とある人が同じように季節の名前を持ったライブラリを作っていますが、MomijiやAkiの名前と何か関係が？
ありません。

### 本当？
本当だお

### 本当の本当？
...黙秘します。
