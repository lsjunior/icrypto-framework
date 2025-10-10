package com.github.lsjunior.icrypto.core.util;

import java.sql.Time;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Calendar;
import java.util.Date;

public abstract class Dates {

  public static Date toStartOfDay(final Date date) {
    if (date == null) {
      return null;
    }
    LocalDateTime localDateTime = Dates.toStartOfDay(Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime());
    return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
  }

  public static LocalDateTime toStartOfDay(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    return localDateTime.withHour(0).withMinute(0).withSecond(0).withNano(0);
  }

  public static LocalDateTime toStartOfDay(final LocalDate localDate) {
    if (localDate == null) {
      return null;
    }
    return localDate.atStartOfDay();
  }

  public static Date toEndOfDay(final Date date) {
    if (date == null) {
      return null;
    }
    LocalDateTime localDateTime = Dates.toEndOfDay(Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime());
    return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
  }

  public static LocalDateTime toEndOfDay(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    return localDateTime.withHour(23).withMinute(59).withSecond(59).withNano(0);
  }

  public static LocalDateTime toStartOfWeek(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    LocalDateTime startOfDay = Dates.toStartOfDay(localDateTime);
    DayOfWeek dayOfWeek = startOfDay.getDayOfWeek();
    while (dayOfWeek != DayOfWeek.SUNDAY) {
      startOfDay = startOfDay.minusDays(1);
      dayOfWeek = startOfDay.getDayOfWeek();
    }
    return startOfDay;
  }

  public static LocalDateTime toEndOfWeek(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    LocalDateTime endOfDay = Dates.toEndOfDay(localDateTime);
    DayOfWeek dayOfWeek = endOfDay.getDayOfWeek();
    while (dayOfWeek != DayOfWeek.SATURDAY) {
      endOfDay = endOfDay.plusDays(1);
      dayOfWeek = endOfDay.getDayOfWeek();
    }
    return endOfDay;
  }

  public static LocalDateTime toStartOfMonth(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    LocalDateTime startOfDay = Dates.toStartOfDay(localDateTime).withDayOfMonth(1);
    return startOfDay;
  }

  public static LocalDateTime toStartOfMonth(final YearMonth yearMonth) {
    if (yearMonth == null) {
      return null;
    }
    LocalDate localDate = yearMonth.atDay(1);
    return Dates.toStartOfDay(localDate);
  }

  public static LocalDateTime toEndOfMonth(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    LocalDateTime newDate = Dates.toEndOfDay(localDateTime).withDayOfMonth(1).plusMonths(1).minusDays(1);
    return newDate;
  }

  public static LocalDateTime toEndOfMonth(final YearMonth yearMonth) {
    if (yearMonth == null) {
      return null;
    }
    LocalDate localDate = yearMonth.atEndOfMonth();
    return Dates.toStartOfDay(localDate);
  }

  public static LocalDateTime toEndOfDay(final LocalDate localDate) {
    if (localDate == null) {
      return null;
    }
    return localDate.atTime(LocalTime.MAX);
  }

  public static Date toDate(final LocalDate localDate) {
    if (localDate == null) {
      return null;
    }
    return Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
  }

  public static Date toDate(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
  }

  public static Date toDate(final ZonedDateTime zonedDateTime) {
    if (zonedDateTime == null) {
      return null;
    }
    return Date.from(zonedDateTime.toInstant());
  }

  public static Calendar toCalendar(final LocalDate localDate) {
    if (localDate == null) {
      return null;
    }
    Date date = Dates.toDate(localDate);
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(date);
    return calendar;
  }

  public static Calendar toCalendar(final LocalDateTime localDateTime) {
    if (localDateTime == null) {
      return null;
    }
    Date date = Dates.toDate(localDateTime);
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(date);
    return calendar;
  }

  public static Time toTime(final LocalTime localTime) {
    if (localTime == null) {
      return null;
    }
    return Time.valueOf(localTime);
  }

  public static LocalDate toLocalDate(final Date date) {
    if (date == null) {
      return null;
    }
    return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDate();
  }

  public static LocalDateTime toLocalDateTime(final Date date) {
    if (date == null) {
      return null;
    }
    return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime();
  }

  public static LocalTime toLocalTime(final Time time) {
    if (time == null) {
      return null;
    }
    return time.toLocalTime();
  }

  public static LocalTime toLocalTime(final Date date) {
    if (date == null) {
      return null;
    }
    return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalTime();
  }

  public static ZonedDateTime toZonedDateTime(final Date date) {
    if (date == null) {
      return null;
    }
    return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault());
  }

}
