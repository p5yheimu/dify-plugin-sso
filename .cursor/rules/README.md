# Dify SSO Plugin - プロダクトルール・ガイドライン

## 📋 概要

このディレクトリには、Dify SSO Pluginの開発におけるプロダクトマネージャー視点での方向性と開発ガイドラインが含まれています。

## 📁 ファイル構成

### プロダクト戦略・方向性
- **[product-vision.md](./product-vision.md)** - プロダクトビジョン、戦略目標、市場機会
- **[user-personas.md](./user-personas.md)** - ユーザーペルソナ、使用シナリオ、機能優先順位
- **[feature-roadmap.md](./feature-roadmap.md)** - 機能要件、ロードマップ、成功指標
- **[product-principles.md](./product-principles.md)** - プロダクト原則、意思決定指針、ステークホルダー管理

### 技術・開発ガイドライン
- **[technical-architecture.md](./technical-architecture.md)** - 技術アーキテクチャ、制約、開発プロセス
- **[development-guidelines.md](./development-guidelines.md)** - Dify特有の開発ルール、実装規約
- **[security-guidelines.md](./security-guidelines.md)** - セキュリティ基準、脆弱性対策、監査要件
- **[testing-guidelines.md](./testing-guidelines.md)** - テスト戦略、品質基準、CI/CD要件

## 🎯 活用方法

### 新規開発者向け
1. **[product-vision.md](./product-vision.md)** でプロダクトの全体像を理解
2. **[user-personas.md](./user-personas.md)** で対象ユーザーを把握
3. **[technical-architecture.md](./technical-architecture.md)** で技術方針を確認
4. **[development-guidelines.md](./development-guidelines.md)** で具体的な実装方法を学習

### プロダクトマネージャー向け
1. **[product-principles.md](./product-principles.md)** で意思決定フレームワークを確認
2. **[feature-roadmap.md](./feature-roadmap.md)** で機能優先順位を検討
3. **[user-personas.md](./user-personas.md)** で顧客ニーズを再確認

### 品質保証・セキュリティ担当者向け
1. **[security-guidelines.md](./security-guidelines.md)** でセキュリティ要件を確認
2. **[testing-guidelines.md](./testing-guidelines.md)** でテスト基準を把握

## 🔄 更新・メンテナンス

### 更新頻度
- **プロダクト戦略**: 四半期レビュー
- **ユーザーペルソナ**: 半年レビュー
- **技術ガイドライン**: 必要に応じて随時更新
- **セキュリティ要件**: セキュリティ監査後に更新

### 更新プロセス
1. 変更提案をIssue/PRで作成
2. 関連ステークホルダーとレビュー
3. 承認後、ドキュメント更新
4. チーム全体への変更通知

## 🎪 重要な原則

### セキュリティファースト
- 全ての実装においてセキュリティを最優先
- OWASP Top 10の脆弱性対策必須
- 継続的なセキュリティ監査実施

### ユーザー中心設計
- IT管理者の運用効率を重視
- 開発者の統合容易性を確保
- エンドユーザーの認証体験を最適化

### エンタープライズ品質
- 99.9%以上の可用性
- 完全な監査ログ記録
- コンプライアンス要件への完全対応

## 📞 お問い合わせ

ドキュメントに関する質問や改善提案は、以下の方法でお知らせください：

- **技術的質問**: 開発チームSlackチャンネル
- **プロダクト戦略**: プロダクトマネージャーまで直接連絡
- **セキュリティ関連**: セキュリティチームまで

## 🔗 関連リンク

- [Dify Plugin SDK Documentation](https://docs.dify.ai/plugins)
- [SAML 2.0 Specification](https://docs.oasis-open.org/security/saml/v2.0/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/connect/)

---

**注意**: これらのドキュメントは、Dify SSO Pluginの品質と方向性を保つための重要な指針です。開発前に必ず確認し、不明な点があれば積極的に質問してください。 