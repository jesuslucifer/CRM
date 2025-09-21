import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Separator } from "@/components/ui/separator"
import { useProfile } from "@/shared/hooks/useProfile"
import ProfileEditForm from "./ProfileEditForm"
import { useState } from "react"

export default function ProfilePage() {
    const {user, isLoading} = useProfile();

const [edit, setEdit] = useState(false)
  const companies = [
    { id: 1, name: "ООО «Моя Компания»", role: "Администратор" },
    { id: 2, name: "CRM Startup", role: "Сотрудник" },
  ]

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-10">
      <Card className="w-full max-w-3xl shadow-lg">
        <CardHeader>
          <CardTitle className="text-2xl">Профиль пользователя</CardTitle>
          <CardDescription>
            Управляйте личной информацией и компаниями
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-8">
          <div className="flex items-center gap-6">
            <Avatar className="h-20 w-20 border">
              <AvatarImage src="https://github.com/shadcn.png" alt="Avatar" />
              <AvatarFallback>U</AvatarFallback>
            </Avatar>
            <div className="flex flex-col">
              <span className="text-xl font-semibold">
                {user?.username}
              </span>
              <span className="text-gray-500">{user?.email}</span>
              <Button variant="outline" size="sm" className="mt-2 w-fit">
                Загрузить новый аватар
              </Button>
            </div>
          </div>
          <Separator />
          {
            edit ? <div>
                    <ProfileEditForm user={user}/>
                <Button onClick={() => setEdit(false)}>Отменить</Button>
            </div>
             
            
            : <Button onClick={() => setEdit(true)}>Редактировать профиль</Button>
          }
                
          <Separator />
          <div>
            <h2 className="text-xl font-semibold mb-4">Мои компании</h2>
            <div className="grid gap-4 md:grid-cols-2">
              {companies.map((company) => (
                <Card key={company.id} className="border shadow-sm">
                  <CardHeader>
                    <CardTitle className="text-lg">{company.name}</CardTitle>
                    <CardDescription>{company.role}</CardDescription>
                  </CardHeader>
                </Card>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
