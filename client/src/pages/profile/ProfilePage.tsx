
import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Separator } from "@/components/ui/separator"
import { useProfile } from "@/shared/hooks/useProfile"
import ProfileEditForm from "./ProfileEditForm"
import { useState } from "react"

import { authService } from "@/service/auth.service"
import { useNavigate } from "react-router"
import { Input } from "@/components/ui/input"
import ProfileInfo from "@/features/profile/ProfileInfo"


export default function ProfilePage() {
  const { user } = useProfile()
  const [edit, setEdit] = useState(false)
  const navigate = useNavigate()


  return (
    <div className="min-h-screen bg-slate-50 p-8 space-y-8">


      <div className="bg-white rounded-3xl shadow-xl p-8 flex flex-col md:flex-row md:items-center md:justify-between gap-6 transition hover:shadow-2xl">

        <div className="flex items-center gap-6">
          <Avatar className="h-24 w-24 shadow-lg ring-4 ring-indigo-100">
            <AvatarImage src="https://github.com/shadcn.png" />

            <AvatarFallback className="text-xl">
              {user?.username?.charAt(0)}
            </AvatarFallback>
          </Avatar>

          <div>
            <h1 className="text-2xl font-bold">{user?.username}</h1>
            <p className="text-slate-500">{user?.email}</p>

            <Button
              variant="outline"
              size="sm"
              className="mt-3 rounded-xl hover:scale-105 transition"
            >
              Загрузить новый аватар
            </Button>
          </div>
        </div>

        <Button
          onClick={() => {
            authService.logout()
            navigate("/login")
          }}
          className="bg-rose-100 text-rose-600 hover:bg-rose-200 rounded-xl transition"
        >
          Выйти из аккаунта
        </Button>
      </div>

      <ProfileInfo />




    </div>
  )
}