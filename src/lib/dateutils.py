# TODO trying to make the convert to date thing

def date_difference(earlier, later):
    '''
    Calculates the positive difference between two dates.
    Tolerant of passsing either date first.
    Dates accepted in formats like 2019-06-22T04:00:23-07:00.
    '''
    # Hour is in military time.
    fstring = "%Y-%m-%dT%H:%M:%S%z"
    # Rip final colon out so the dates are parseable.
    earlier = earlier[:-3] + earlier[-2:]
    later = later[:-3] + later[-2:]
    # Convert to datetimes.
    early_date = datetime.strptime(earlier, fstring)
    late_date = datetime.strptime(later, fstring)
    # If the earlier date isn't really earlier, switch.
    if early_date > late_date:
        late_date, early_date = early_date, late_date
    # Calculate difference.
    difference = late_date - early_date
    return difference.days