
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { useProfile } from "@/shared/hooks/useProfile"
import { useState } from "react"

import ProfileEditForm from "@/pages/profile/ProfileEditForm"


export default function ProfileInfo() {
    const { user } = useProfile()
    const [edit, setEdit] = useState(false)


    return (
        <div className="min-h-screen bg-slate-50 p-8 space-y-8">



            <div className="bg-white rounded-3xl shadow-xl p-8 transition hover:shadow-2xl">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-semibold">Личная информация</h2>

                    {!edit && (
                        <Button
                            onClick={() => setEdit(true)}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition"
                        >
                            Редактировать
                        </Button>
                    )}
                </div>

                <Separator className="mb-6" />

                {edit ? (
                    <div className="space-y-4">
                        <ProfileEditForm user={user} />
                        <div className="flex justify-end">
                            <Button
                                variant="outline"
                                onClick={() => setEdit(false)}
                                className="rounded-xl"
                            >
                                Отменить
                            </Button>
                        </div>
                    </div>
                ) : (
                    <div className="grid md:grid-cols-2 gap-6 text-sm">
                        <div>
                            <p className="text-slate-500">Имя пользователя</p>
                            <p className="font-medium">{user?.username}</p>
                        </div>
                        <div>
                            <p className="text-slate-500">Email</p>
                            <p className="font-medium">{user?.email}</p>
                        </div>

                        <div>
                            <p className="text-slate-500">Имя</p>
                            <p className="font-medium">{user?.name || 'Нет данных'}</p>
                        </div>
                        <div>
                            <p className="text-slate-500">Фамилия</p>
                            <p className="font-medium">{user?.last_name || 'Нет данных'}</p>
                        </div>
                    </div>
                )}
            </div>



        </div>
    )
}