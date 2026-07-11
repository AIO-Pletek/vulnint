"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { auth } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace(auth.getAccess() ? "/dashboard/overview" : "/login");
  }, [router]);
  return null;
}
