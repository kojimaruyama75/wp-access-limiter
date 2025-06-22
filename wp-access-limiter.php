<?php
/**
 * Plugin Name: WP Access Limiter
 * Plugin URI: https://example.com/wp-access-limiter
 * Description: WordPressの管理画面への同時アクセス数を制限するプラグイン
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://example.com
 * License: GPL-2.0+
 */

// 直接アクセス禁止
if (!defined('ABSPATH')) {
    exit;
}

class WP_Access_Limiter {
    // デフォルト設定
    private $default_options = [
        'max_users' => 2,  // 同時アクセス上限
        'admin_exempt' => true, // 管理者は制限から除外するか
        'message' => '現在、管理画面の同時アクセス上限に達しています。しばらくしてから再度お試しください。',
    ];

    public function __construct() {
        // アクションとフィルターの登録
        add_action('init', [$this, 'init']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('wp_login', [$this, 'check_login_limits'], 10, 2);
        add_action('wp_logout', [$this, 'remove_active_session']);

        // Ajax処理の登録
        add_action('wp_ajax_refresh_active_users', [$this, 'ajax_refresh_active_users']);

        // プラグインの有効化/無効化時の処理
        register_activation_hook(__FILE__, [$this, 'plugin_activation']);
        register_deactivation_hook(__FILE__, [$this, 'plugin_deactivation']);
    }

    /**
     * 初期化処理
     */
    public function init() {
        // セッション管理を開始
        if (!session_id()) {
            session_start();
        }
    }

    /**
     * 管理画面の初期化処理
     */
    public function admin_init() {
        // 設定の登録
        register_setting(
            'wp_access_limiter_settings',
            'wp_access_limiter_options',
            [$this, 'validate_options']
        );

        // アクティブセッションの更新
        $this->update_active_session();

        // セッションクリーンアップ処理
        $this->cleanup_expired_sessions();
    }

    /**
     * プラグイン有効化時の処理
     */
    public function plugin_activation() {
        // オプションの初期設定
        if (!get_option('wp_access_limiter_options')) {
            add_option('wp_access_limiter_options', $this->default_options);
        }

        // アクティブセッション保存用テーブルの作成
        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            $charset_collate = $wpdb->get_charset_collate();

            $sql = "CREATE TABLE $table_name (
                id mediumint(9) NOT NULL AUTO_INCREMENT,
                user_id bigint(20) NOT NULL,
                session_id varchar(255) NOT NULL,
                login_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                last_activity datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                ip_address varchar(100) NOT NULL,
                user_agent text NOT NULL,
                PRIMARY KEY  (id),
                KEY user_id (user_id),
                KEY session_id (session_id)
            ) $charset_collate;";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
        }
    }

    /**
     * プラグイン無効化時の処理
     */
    public function plugin_deactivation() {
        // 必要に応じてテーブルの削除などを実装
    }

    /**
     * 設定ページの追加
     */
    public function add_settings_page() {
        add_options_page(
            '管理画面アクセス制限設定',
            'アクセス制限',
            'manage_options',
            'wp-access-limiter',
            [$this, 'render_settings_page']
        );
    }

    /**
     * 設定ページの表示
     */
    public function render_settings_page() {
        // 現在のアクティブセッション数を取得
        $active_sessions = $this->get_active_sessions();
        $options = get_option('wp_access_limiter_options', $this->default_options);
        ?>
        <div class="wrap">
            <h1>管理画面アクセス制限設定</h1>

            <div class="active-users-info">
                <h2>現在のアクティブユーザー数</h2>
                <p><span id="active-user-count"><?php echo count($active_sessions); ?></span> / <?php echo esc_html($options['max_users']); ?></p>
                <button type="button" class="button button-secondary" id="refresh-active-users">更新</button>

                <?php if (!empty($active_sessions)): ?>
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th>ユーザー名</th>
                            <th>ログイン時間</th>
                            <th>最終アクティビティ</th>
                            <th>IPアドレス</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="active-users-list">
                        <?php foreach ($active_sessions as $session): ?>
                            <?php $user = get_userdata($session->user_id); ?>
                            <tr>
                                <td><?php echo esc_html($user ? $user->display_name : '不明なユーザー'); ?></td>
                                <td><?php echo esc_html($session->login_time); ?></td>
                                <td><?php echo esc_html($session->last_activity); ?></td>
                                <td><?php echo esc_html($session->ip_address); ?></td>
                                <td>
                                    <button type="button" class="button button-small button-link-delete disconnect-user" data-session-id="<?php echo esc_attr($session->session_id); ?>">切断</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>

            <form method="post" action="options.php">
                <?php settings_fields('wp_access_limiter_settings'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">最大同時ログインユーザー数</th>
                        <td>
                            <input type="number" name="wp_access_limiter_options[max_users]" value="<?php echo esc_attr($options['max_users']); ?>" min="1" max="100" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">管理者を制限から除外</th>
                        <td>
                            <input type="checkbox" name="wp_access_limiter_options[admin_exempt]" value="1" <?php checked(1, $options['admin_exempt']); ?> />
                            <span class="description">管理者権限を持つユーザーは上限にカウントしない</span>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">制限メッセージ</th>
                        <td>
                            <textarea name="wp_access_limiter_options[message]" rows="3" cols="50"><?php echo esc_textarea($options['message']); ?></textarea>
                            <p class="description">上限に達した場合に表示するメッセージ</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>

        <script type="text/javascript">
        jQuery(document).ready(function($) {
            // アクティブユーザー情報の更新
            $('#refresh-active-users').on('click', function() {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'refresh_active_users'
                    },
                    success: function(response) {
                        if (response.success) {
                            $('#active-user-count').text(response.data.count);
                            $('#active-users-list').html(response.data.html);
                        }
                    }
                });
            });

            // ユーザー切断処理
            $(document).on('click', '.disconnect-user', function() {
                var sessionId = $(this).data('session-id');
                if (confirm('このユーザーを切断してもよろしいですか？')) {
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'disconnect_user',
                            session_id: sessionId
                        },
                        success: function(response) {
                            if (response.success) {
                                $('#refresh-active-users').trigger('click');
                            }
                        }
                    });
                }
            });
        });
        </script>
        <?php
    }

    /**
     * 設定の検証
     */
    public function validate_options($input) {
        $output = [];

        // 最大ユーザー数の検証
        $output['max_users'] = intval($input['max_users']);
        if ($output['max_users'] < 1) {
            $output['max_users'] = 1;
        }

        // 管理者除外設定
        $output['admin_exempt'] = isset($input['admin_exempt']) ? 1 : 0;

        // メッセージの検証
        $output['message'] = sanitize_textarea_field($input['message']);

        return $output;
    }

    /**
     * アクティブセッションのリフレッシュ（Ajax）
     */
    public function ajax_refresh_active_users() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('権限がありません');
            return;
        }

        $active_sessions = $this->get_active_sessions();
        $html = '';

        foreach ($active_sessions as $session) {
            $user = get_userdata($session->user_id);
            $html .= '<tr>';
            $html .= '<td>' . esc_html($user ? $user->display_name : '不明なユーザー') . '</td>';
            $html .= '<td>' . esc_html($session->login_time) . '</td>';
            $html .= '<td>' . esc_html($session->last_activity) . '</td>';
            $html .= '<td>' . esc_html($session->ip_address) . '</td>';
            $html .= '<td><button type="button" class="button button-small button-link-delete disconnect-user" data-session-id="' . esc_attr($session->session_id) . '">切断</button></td>';
            $html .= '</tr>';
        }

        wp_send_json_success([
            'count' => count($active_sessions),
            'html' => $html
        ]);
    }

    /**
     * ログイン時のアクセス制限チェック
     */
    public function check_login_limits($user_login, $user) {
        $options = get_option('wp_access_limiter_options', $this->default_options);

        // 管理者は除外する設定の場合
        if ($options['admin_exempt'] && user_can($user, 'manage_options')) {
            $this->add_active_session($user->ID);
            return;
        }

        // 現在のアクティブセッション数を取得
        $active_sessions = $this->get_active_sessions();

        // 同一ユーザーが既にログインしているか確認
        foreach ($active_sessions as $session) {
            if ($session->user_id == $user->ID) {
                // 既存のセッションを更新
                $this->update_session($session->session_id);
                return;
            }
        }

        // 上限に達しているか確認
        if (count($active_sessions) >= $options['max_users']) {
            // ログアウトさせる
            wp_logout();

            // エラーメッセージを表示して管理画面へのアクセスをブロック
            wp_die(
                $options['message'],
                'アクセス制限',
                [
                    'response' => 403,
                    'back_link' => true,
                ]
            );
        }

        // 新しいセッションを追加
        $this->add_active_session($user->ID);
    }

    /**
     * アクティブセッションの追加
     */
    private function add_active_session($user_id) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        $wpdb->insert(
            $table_name,
            [
                'user_id' => $user_id,
                'session_id' => session_id(),
                'login_time' => current_time('mysql'),
                'last_activity' => current_time('mysql'),
                'ip_address' => $this->get_client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            ],
            [
                '%d',
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
            ]
        );
    }

    /**
     * 既存セッションの更新
     */
    private function update_session($session_id) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        $wpdb->update(
            $table_name,
            [
                'last_activity' => current_time('mysql'),
                'ip_address' => $this->get_client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            ],
            [
                'session_id' => $session_id,
            ],
            [
                '%s',
                '%s',
                '%s',
            ],
            [
                '%s',
            ]
        );
    }

    /**
     * 現在のセッションを更新
     */
    private function update_active_session() {
        if (!is_user_logged_in()) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        $wpdb->update(
            $table_name,
            [
                'last_activity' => current_time('mysql'),
            ],
            [
                'session_id' => session_id(),
            ],
            [
                '%s',
            ],
            [
                '%s',
            ]
        );
    }

    /**
     * ログアウト時のセッション削除
     */
    public function remove_active_session() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        $wpdb->delete(
            $table_name,
            [
                'session_id' => session_id(),
            ],
            [
                '%s',
            ]
        );
    }

    /**
     * アクティブセッションの取得
     */
    private function get_active_sessions() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        // 30分以内にアクティビティのあるセッションを取得
        $timeout = date('Y-m-d H:i:s', strtotime('-30 minutes'));

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table_name WHERE last_activity > %s ORDER BY last_activity DESC",
                $timeout
            )
        );
    }

    /**
     * 期限切れセッションのクリーンアップ
     */
    private function cleanup_expired_sessions() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'access_limiter_sessions';

        // 30分以上アクティビティのないセッションを削除
        $timeout = date('Y-m-d H:i:s', strtotime('-30 minutes'));

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE last_activity < %s",
                $timeout
            )
        );
    }

    /**
     * クライアントIPアドレスの取得
     */
    private function get_client_ip() {
        $ip_keys = [
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];

        foreach ($ip_keys as $key) {
            if (isset($_SERVER[$key])) {
                $ip_array = explode(',', $_SERVER[$key]);
                $ip = trim($ip_array[0]);

                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
}

// プラグインのインスタンス化
$wp_access_limiter = new WP_Access_Limiter();
