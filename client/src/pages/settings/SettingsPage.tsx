import ChangeEmailPage from "../auth/ChangeEmailPage";
import ChangePasswordPage from "../auth/ChangePasswordPage";

export default function SettingsPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 p-8">
      <div className="max-w-6xl mx-auto space-y-10">

        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Настройки</h1>
          <p className="text-slate-500 mt-1">
            Управление безопасностью и параметрами аккаунта
          </p>
        </div>

        {/* System settings */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white rounded-3xl shadow-sm border p-6 hover:shadow-md transition">
            <h2 className="font-semibold text-lg mb-2">Общие настройки</h2>
            <p className="text-sm text-slate-500">
              Базовые параметры системы
            </p>
          </div>

          <div className="bg-white rounded-3xl shadow-sm border p-6 hover:shadow-md transition">
            <h2 className="font-semibold text-lg mb-2">Пользователи и роли</h2>
            <p className="text-sm text-slate-500">
              Управление доступами
            </p>
          </div>

          <div className="bg-white rounded-3xl shadow-sm border p-6 hover:shadow-md transition">
            <h2 className="font-semibold text-lg mb-2">Воронки</h2>
            <p className="text-sm text-slate-500">
              Настройка бизнес-процессов
            </p>
          </div>
        </div>

        {/* Security section */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <ChangePasswordPage />
          <ChangeEmailPage />
        </div>

      </div>
    </div>
  );
}