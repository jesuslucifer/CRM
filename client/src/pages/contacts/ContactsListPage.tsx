export default function ContactsListPage() {
  return (
    <div className="p-8 space-y-6 bg-slate-50 min-h-screen">

      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Клиенты</h1>
        <button className="bg-gradient-to-r from-indigo-600 to-emerald-500 text-white px-5 py-2 rounded-xl shadow-lg hover:scale-105 transition">
          + Добавить клиента
        </button>
      </div>

      <div className="bg-white rounded-3xl shadow-xl border border-slate-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-100 text-slate-600">
            <tr className="text-left">
              <th className="py-4 px-4">ФИО</th>
              <th className="py-4 px-4">Тип клиента</th>
              <th className="py-4 px-4">Объект интереса</th>
              <th className="py-4 px-4">Email</th>
              <th className="py-4 px-4">Телефон</th>
              <th className="py-4 px-4">Статус</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2].map((id) => (
              <tr
                key={id}
                className="border-t hover:bg-slate-50 transition"
              >
                <td className="py-4 px-4 font-medium">Иван Петров {id}</td>
                <td className="py-4 px-4">Покупатель</td>
                <td className="py-4 px-4">Квартира • Москва</td>
                <td className="py-4 px-4">client{id}@mail.ru</td>
                <td className="py-4 px-4">+7 999 000 00{id}</td>
                <td className="py-4 px-4">
                  <span className="bg-emerald-100 text-emerald-600 px-3 py-1 rounded-full text-xs">
                    Активный
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}