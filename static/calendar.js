document.addEventListener('DOMContentLoaded', function() {
    const initialDataEl = document.getElementById('initial-data');
    let tasks = JSON.parse(initialDataEl.dataset.tasks);
    var calendarEl = document.getElementById('calendar');

    function getTasksForDate(date, tasks) {
        const dayOfWeek = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'][date.getUTCDay()];
        const dateString = date.toISOString().slice(0, 10);

        return tasks.filter(task => {
            if (task.isOneTime) {
                return task.date === dateString;
            }
            return task.recurrence.includes('Daily') || task.recurrence.includes(dayOfWeek);
        });
    }

    function generateAllEvents(tasks) {
        const events = [];
        const today = new Date();
        const startDate = new Date(today.getFullYear() - 1, today.getMonth(), 1);
        const endDate = new Date(today.getFullYear() + 1, today.getMonth(), 0);

        for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
            const tasksForDay = getTasksForDate(new Date(d), tasks);
            tasksForDay.forEach(task => {
                events.push({
                    title: task.text,
                    start: new Date(d).toISOString().slice(0, 10),
                    allDay: true,
                    extendedProps: {
                        taskId: task.id
                    }
                });
            });
        }
        return events;
    }

    var calendar = new FullCalendar.Calendar(calendarEl, {
      initialView: 'dayGridMonth',
      headerToolbar: {
        left: 'prev,next today',
        center: 'title',
        right: 'dayGridMonth,timeGridWeek,timeGridDay'
      },
      events: generateAllEvents(tasks),
      eventClick: function(info) {
        // Here you can add logic to open the task modal
        console.log('Event: ' + info.event.title);
      }
    });

    calendar.render();
  });