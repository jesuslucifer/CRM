export default function LeadsListPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Leads</h1>
      <div className="bg-white rounded-2xl shadow p-4">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b">
              <th className="py-2 px-3">Name</th>
              <th className="py-2 px-3">Email</th>
              <th className="py-2 px-3">Phone</th>
              <th className="py-2 px-3">Source</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3].map((id) => (
              <tr key={id} className="border-b hover:bg-gray-50">
                <td className="py-2 px-3">Lead {id}</td>
                <td className="py-2 px-3">lead{id}@mail.com</td>
                <td className="py-2 px-3">+123456789</td>
                <td className="py-2 px-3">Website</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
