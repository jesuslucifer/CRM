export default function DealsKanbanPage() {
  const stages = [
    { name: "Новые", color: "bg-indigo-100 text-indigo-600" },
    { name: "В работе", color: "bg-blue-100 text-blue-600" },
    { name: "Успешно", color: "bg-emerald-100 text-emerald-600" },
    { name: "Потеряно", color: "bg-rose-100 text-rose-600" },
  ]

  return (
    <div className="p-8 bg-slate-50 min-h-screen space-y-6">
      <h1 className="text-3xl font-bold">Канбан сделок</h1>

      <div className="flex gap-6 overflow-x-auto pb-4">
        {stages.map((stage) => (
          <div
            key={stage.name}
            className="w-80 bg-white rounded-3xl shadow-xl p-4 flex-shrink-0"
          >
            <h2 className={`text-sm font-semibold px-3 py-1 rounded-full inline-block ${stage.color}`}>
              {stage.name}
            </h2>

            <div className="space-y-4 mt-4">
              {[1, 2].map((id) => (
                <div
                  key={id}
                  className="bg-slate-50 rounded-2xl p-4 hover:shadow-md hover:scale-105 transition"
                >
                  <p className="font-semibold">Продажа дома №{id}</p>
                  <p className="text-sm text-slate-500 mt-1">
                    12 000 000 ₽ • Иван Петров
                  </p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}