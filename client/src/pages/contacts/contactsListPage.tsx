export default function ContactsListPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Contacts</h1>
      <div className="bg-white rounded-2xl shadow p-4">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b">
              <th className="py-2 px-3">Name</th>
              <th className="py-2 px-3">Position</th>
              <th className="py-2 px-3">Company</th>
              <th className="py-2 px-3">Email</th>
              <th className="py-2 px-3">Phone</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2].map((id) => (
              <tr key={id} className="border-b hover:bg-gray-50">
                <td className="py-2 px-3">John Doe {id}</td>
                <td className="py-2 px-3">Manager</td>
                <td className="py-2 px-3">Acme Inc.</td>
                <td className="py-2 px-3">john{id}@mail.com</td>
                <td className="py-2 px-3">+987654321</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
