export default function DealsListPage() {
  return (
    <div className="p-8 space-y-6 bg-slate-50 min-h-screen">

      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Сделки</h1>
        <button className="bg-indigo-600 text-white px-5 py-2 rounded-xl shadow-lg hover:scale-105 transition">
          + Новая сделка
        </button>
      </div>

      <div className="bg-white rounded-3xl shadow-xl border border-slate-200 p-6">

        <input
          className="mb-6 border rounded-xl px-4 py-2 w-80 focus:ring-2 focus:ring-indigo-500 transition"
          placeholder="Поиск по объекту или клиенту..."
        />

        <table className="w-full text-sm">
          <thead className="text-slate-600 border-b">
            <tr>
              <th className="py-3 px-3 text-left">Объект</th>
              <th className="py-3 px-3 text-left">Сумма</th>
              <th className="py-3 px-3 text-left">Этап</th>
              <th className="py-3 px-3 text-left">Ответственный</th>
              <th className="py-3 px-3 text-left">Действия</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3].map((id) => (
              <tr key={id} className="border-t hover:bg-slate-50 transition">
                <td className="py-3 px-3 font-medium">
                  Продажа квартиры №{id}
                </td>
                <td className="py-3 px-3">8 500 000 ₽</td>
                <td className="py-3 px-3">
                  <span className="bg-indigo-100 text-indigo-600 px-3 py-1 rounded-full text-xs">
                    Переговоры
                  </span>
                </td>
                <td className="py-3 px-3">Алексей Смирнов</td>
                <td className="py-3 px-3 text-indigo-600 hover:underline cursor-pointer">
                  Открыть
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}